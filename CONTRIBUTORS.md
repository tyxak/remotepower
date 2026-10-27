# Contributors

RemotePower is maintained by **Jakob Munch Overgaard** (@tyxak).

Thanks to everyone who has contributed fixes, features, and reports.

## Contributors

- **Thomas Bouquet-Gasparoux** (@tbouquet) — first contributed in v5.1.0:
  - #3 — anchor both branches of `_IP_RE` so `_sanitize_ip` rejects trailing garbage
  - #4 — honour `disk_watchdog_pct=0` (off) in the `/api/self-test` disk check
  - #5 — accept a bare-list body in `handle_drift_policies_set`
  - #6 — invalidate the RAG embedding cache when the embedding model/provider changes
  - #7 — CGI import shim so the backend isn't recompiled on every request
  - #8 — reported the device-write read-modify-write race (lost update / row
    deletion on the SQL backend)
  - in v5.1.1:
  - #9 — list Proxmox guests across the whole cluster (per-node resolution for
    every lifecycle action), not just the configured node
  - #12 — restore the page named in the URL hash on refresh instead of always
    dropping back to home
  - #14 — bypass the HTTP cache when the service worker pre-caches the app shell
    (so a stale shell can't be re-cached after an upgrade)
  - #16 — don't hand the WireGuard hub's private key to the unprivileged caller
    (security hardening of the WG Access apply path)
- **@loryanstrant** — first contributed in v5.1.1:
  - #10 — reported that the API-key field was blocked for LocalAI (which now
    supports API keys for per-app usage tracking)
  - #11 — requested the ability to run embeddings on a different provider/service
    than chat (separate embedding endpoint + key)
- **@AndiBSE** — first contributed in v5.7.0:
  - #17 — reported that devices could not be deleted (the drawer's Remove action
    called an undefined function and silently threw)
  - #18 — reported the account/profile menu was unreadable in light mode
  - #19 — reported the accent-colour picker was ignored in the New UI (and, in
    follow-up, that full themes and the accent on chamfered buttons in light mode
    were affected by the same class of bug)
  - #20 — reported devices showing offline from an ICMP/ping reachability issue
    (fixed with a ping fallback so a host that answers ping isn't marked down)
  - #21 — reported fleet service baselines weren't applying — scoped
    (group/tag/site) baselines were never merged in, and the save/list API hit a
    doubled `/api/api/…` path (404); both fixed
- **@shrekki1816** — first contributed in v6.0.1:
  - #22 — reported the New Script dialog gave no visual feedback on save (it only
    closed after an edit, not when creating a new script)
- **@SCR7575** — first contributed in v7.4.1:
  - #32 — reported that a host's poll interval was refused below 30 seconds while
    the fleet default is 10, and, in a comment, that enrolling a host again left
    the running agent on the old credentials
  - #33 — reported the scanner container always showing as unhealthy
  - #34 — reported that the installer's CA fingerprint check failed against a
    self-signed server, that the port the dashboard was opened on never reached
    the server, and that the quick-install line failed without saying why
  - #35 — reported the auto-hide sidebar being unusable on a touch screen
  - #36 — asked for the web terminal in the Docker image
  - #37 — asked for NIC errors and drops to be judged separately, with
    per-host thresholds
  - #38 — reported that a default watched file the host never had alerted as
    removed
  - #39 — asked for folders and patterns in the drift watch, and for per-host
    lists that add to the default
  - #40 — asked for a way to turn off a thinking model's thinking for Ollama
  - #41 — reported that the maintenance window form never showed the cron field
    or the duration
  - #42 — reported that SNMP memory counted the cache as used, so a firewall with a
    quarter of its memory in use read 94% and raised a memory alert
  - #43 — asked for container alert excludes to match the image, not only the name
  - #44 — asked for the integrations bound to a host to show on that host's card
  - #45 — reported that a stopped container's alert never closed, and traced it to
    the agent listing only running containers

---

Contributions are credited by git authorship (preserved on merge) and in the
[CHANGELOG](CHANGELOG.md) entry for the release they ship in.
