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

---

Contributions are credited by git authorship (preserved on merge) and in the
[CHANGELOG](CHANGELOG.md) entry for the release they ship in.
