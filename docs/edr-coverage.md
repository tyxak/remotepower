# EDR coverage

Read-only connectors for **Wazuh**, **CrowdStrike Falcon** and **SentinelOne** —
but the tile is not the feature. Each connector reports the hosts it *protects*,
and RemotePower cross-references that against your actual fleet to name the
machines with **no EDR on them at all**.

> A console reading "EDR: healthy" while three servers are uncovered is worse than
> no console, because it is reassuring. **The gap is the product.**

Surfaced as a card on the **Risk** page, uncovered hosts first. Hidden until an
EDR integration is configured.

## Set it up

Settings → Integrations → add an instance of type `wazuh`, `crowdstrike` or
`sentinelone` with its read-only API credentials. RemotePower polls it on the
integrations cadence and stores the protected-host set.

## What it gets right

**Hostname matching.** Consoles and agents disagree endlessly about case and
domain suffix — `WEB01.corp.example.com` in Falcon is `web01` in your fleet. Match
the raw strings and almost every host reports as uncovered, which teaches
operators to distrust the page. Matching is on the short, lowercased name.

**Stale agents.** The most likely way an EDR rollout fails is not "we forgot a
host" — it is "the agent installed, then stopped reporting". A stale agent is
listed **apart** from a protected one, never folded into the "covered" count,
because that is exactly the case the page exists to surface.

## Why no Microsoft Defender for Endpoint

MDE's OAuth token endpoint lives on a *different host* from its API. The shared
integration client is deliberately **bound to the instance's base URL and refuses
absolute URLs** — that binding is what keeps the SSRF guard meaningful. Loosening
it so one connector could fetch a token from another host would weaken the guard
for every connector. It is left out on purpose.

## API

`GET /api/edr/coverage` — per-host coverage, with a summary (covered / uncovered /
stale) and the vendor(s) protecting each host.

---

← [Back to docs index](README.md)
