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
health (SMART, storage, thermal and OOM). It also reads UEFI Secure Boot,
canary files that could not be placed, files the integrity guard has
quarantined, failed scheduled jobs, containers stuck in a restart loop, your own
custom checks, and whether the host is being attacked right now.

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
  the Checks page shows, including per-host assignment, the disabled list and
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
- **Being attacked counts.** Each source currently over the brute-force
  threshold adds points, and a source that a reputation service lists as
  abusive (score 75 or more in [IP intel](ip-intel.md)) and that is not blocked
  on the host adds more. Both are capped. The sources are the ones the
  brute-force alert and the Security Advisory name, so the three agree.
- **Security updates count on their own.** The part of the pending count your
  distribution calls a security fix scores again, per update and capped, on top
  of the pending updates themselves, because a security fix that is waiting is
  the pending update that matters most. A host that has not reported a count
  scores nothing for it *(7.5.0)*.
- **A Mac's Gatekeeper and System Integrity Protection, and a Windows host's
  Defender signatures, tamper protection and User Account Control, score when
  they are off.** Each protection that is off adds its weight, capped. The
  signatures count once they are as old as the limit for the *Defender
  signatures stale* alert (Settings → Alert parameters), so the score, the alert
  and the Checks row agree. A setting the agent could not read scores nothing
  *(7.5.0)*.
- **A container in a restart loop scores.** The containers counted are the ones
  under an open *container restarting* alert, so the score, the alert and the
  Containers page agree on what a loop is. It clears with the alert *(7.5.0)*.
- **ECC memory errors and NIC errors are not in this score.** The
  [reliability score](disk-health.md#host-reliability-prediction) weighs them as failing hardware, and a
  fault counted in both scores makes both wrong.
- **Every weight is tunable** under Settings → Alert parameters → Risk score
  weights; 0 turns a factor off.
- **Posture booleans are tri-state.** Secure Boot off scores; Secure Boot never
  reported does not. A machine that boots without UEFI tells you nothing, and a
  list of findings should not be padded with hosts that were never asked.
- It is a *prioritisation* aid computed from observed data — not a formal
  risk assessment.

← [Back to docs index](README.md)
