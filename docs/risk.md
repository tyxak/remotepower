# Risk

**Security → Risk** computes a per-asset risk score (0–100) on demand from
everything RemotePower already knows: open CVEs by severity and by **KEV**
membership (accepted-risk findings excluded), world-reachable services,
host firewall state, Windows/macOS endpoint posture (firewall profiles and
BitLocker/FileVault) and disk-encryption-at-rest,
software-policy violations, pending updates and patch-SLA breaches, OS
end-of-life, container-image CVEs, malware/AV posture, exposed credentials,
backup freshness, contract and warranty expiry, config drift, and hardware
health (SMART, storage, thermal, ECC, OOM, and a NIC accumulating errors —
which the reliability score also weighs as failing hardware).

- The score is **explained** — each contributing factor is listed with its
  weight, so "why is this 78" has an answer.
- Sort the fleet by risk to spend attention where it matters; the score
  also feeds the AI advisors and the fleet posture [report](reports.md).
- It is a *prioritisation* aid computed from observed data — not a formal
  risk assessment.
