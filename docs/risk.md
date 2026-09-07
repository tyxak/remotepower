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
which the reliability score also weighs as failing hardware). It also reads
UEFI Secure Boot, canary files that could not be placed, files the integrity
guard has quarantined, failed scheduled jobs, and your own custom checks.

- The score is **explained** — each contributing factor is listed with its
  weight, so "why is this 78" has an answer.
- Sort the fleet by risk to spend attention where it matters; the score
  also feeds the AI advisors and the fleet posture [report](reports.md).
- **sshd hardening and automatic security updates** contribute only when
  *Security hardening* is switched on (Settings → Advanced). Root-login or
  password SSH is often a choice, so those advisories are opt-in —
  and the score follows the same switch rather than moving every host's number
  on a policy you never enabled. The verdicts are the ones the Checks page
  shows, so the two cannot disagree about the same host.
- **Your own checks count.** A custom check in a critical or warning state
  adds to the host's score — a warning at half the weight of a critical, capped
  so forty failing checks do not swamp everything else. The verdict is the one
  the Checks page shows, including per-device assignment, the disabled list and
  an accepted baseline, so the two cannot disagree.
- **A canary that could not be placed is a finding; one that is watching a real
  file is not.** If the agent could not create the decoy, you have a honeytoken
  on your settings page and nothing on the host, which is worth points. If a
  real file was already at that path, it is being watched for change instead —
  weaker than a honeytoken, but not a gap.
- **A failed timer is scored separately from a failed unit.** When a systemd
  timer cannot fire, the job it starts is simply never started, so the unit
  itself still looks fine. Backups and scans go quiet without anything else
  changing.
- **Posture booleans are tri-state.** Secure Boot off scores; Secure Boot never
  reported does not. A machine that boots without UEFI tells you nothing, and a
  list of findings should not be padded with hosts that were never asked.
- It is a *prioritisation* aid computed from observed data — not a formal
  risk assessment.
