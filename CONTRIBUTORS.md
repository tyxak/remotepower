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

---

Contributions are credited by git authorship (preserved on merge) and in the
[CHANGELOG](CHANGELOG.md) entry for the release they ship in.
