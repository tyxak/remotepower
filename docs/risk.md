# Risk

**Security → Risk** computes a per-asset risk score (0–100) on demand from
everything RemotePower already knows: open CVEs (weighted by severity/KEV),
world-reachable services, software-policy violations, pending updates,
container posture, drift, and patch/backup freshness.

- The score is **explained** — each contributing factor is listed with its
  weight, so "why is this 78" has an answer.
- Sort the fleet by risk to spend attention where it matters; the score
  also feeds the AI advisors and the fleet posture [report](reports.md).
- It is a *prioritisation* aid computed from observed data — not a formal
  risk assessment.
