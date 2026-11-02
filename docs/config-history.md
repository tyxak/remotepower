# Configuration history & rollback

Every change to the server configuration is snapshotted, so a setting you didn't
mean to change — or a change that turned out to be wrong — is one click to undo.

## How it works

Whenever the configuration is saved, the **previous** state is appended as a
restorable revision before the new state takes effect. Revisions are capped at
the most recent 10 and are stored with the same `0600` / backing-store
protection as the live configuration itself, so nothing sensitive is exposed by
keeping the history.

- `GET /api/config/revisions` lists the saved revisions (who changed it, when, and
  which keys changed, up to 50), newest first.
- `POST /api/config/revisions/restore` swaps the live configuration for a picked
  revision. The state being replaced is itself saved as a new revision first, so
  a restore is always reversible — you can roll a rollback back.

In the UI the history lives under **Settings → Advanced → Configuration
history**. Each row shows when it was saved, who changed the configuration and which
keys changed. **Restore** swaps the live configuration for that revision after you
confirm, and the page reloads the new values.

Reading the history and restoring from it are instance-admin actions. On an install
with tenants, a tenant admin cannot do either, because the configuration belongs to
the whole install.

## What's captured

The snapshot is of the server configuration (thresholds, channel routing,
integration settings, feature toggles, alert parameters, and so on). Secrets
inside the configuration are handled exactly as they are everywhere else — they
are never echoed back on read; restoring a revision restores the whole
configuration state, including any secret values that were set at the time.

Host records, alerts and other operational stores are not part of this
history — this is specifically the *configuration* audit trail. For a per-alert
or per-host audit, see the audit log and the alert timeline.
