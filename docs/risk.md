# Risk

**Security → Risk** computes a per-asset risk score (0–100) on demand from
everything RemotePower already knows: open CVEs by severity and by **KEV**
membership (accepted-risk findings excluded), world-reachable services,
host firewall state, endpoint posture on every platform (firewall profiles,
BitLocker, FileVault and Linux LUKS/dm-crypt — an unencrypted disk now scores
the same wherever it is),
software-policy violations, pending updates and patch-SLA breaches, OS
end-of-life, container-image CVEs, malware/AV posture, exposed credentials,
backup freshness, contract and warranty expiry, config drift, and hardware
health (SMART, storage, thermal, ECC, OOM, and a NIC accumulating errors —
which the reliability score also weighs as failing hardware).

- The score is **explained** — each contributing factor is listed with its
  weight, so "why is this 78" has an answer.
- Sort the fleet by risk to spend attention where it matters; the score
  also feeds the AI advisors and the fleet posture [report](reports.md).
- **sshd hardening and automatic security updates** contribute only when
  *Security hardening* is switched on (Settings → Advanced). Root-login or
  password SSH is often a deliberate choice, so those advisories are opt-in —
  and the score follows the same switch rather than moving every host's number
  on a policy you never enabled. The verdicts are the ones the Checks page
  shows, so the two cannot disagree about the same host.
- It is a *prioritisation* aid computed from observed data — not a formal
  risk assessment.
