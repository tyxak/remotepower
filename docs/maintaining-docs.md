# Keeping the documentation in sync

RemotePower documents the same features in several places, each for a different
reader. When you add, change, or remove a user-facing feature, update **all** of
these in the same change — a feature that lives in the code but not the docs is
effectively invisible, and a half-updated set of docs is worse than none.

## The surfaces (update every one)

1. **Documentation page (in-app)** — `server/html/index.html`. The Help →
   Documentation cards, including the "What's new — vX.Y.Z" card.
2. **README.md** — the project overview and the "What you can do with it"
   feature list.
3. **Manual.html** — `docs/Manual.html`, the long-form reference: the "what's
   new" list at the top *and* the relevant topic section further down.
4. **Release notes** — `docs/vX.Y.Z.md` for the version that introduces the
   feature.
5. **"Did you know?" tips** — the `_DYK_TIPS` array in
   `server/html/static/js/app.js`. Add a one-line, capability-style tip for any
   feature a user would want to discover.

(The `CHANGELOG.md` entry is separate from these and should also be kept
current.)

## Tone & content rules

- Write for the **public**, in a natural product voice — describe what the user
  can do and why it helps, not how it's implemented internally.
- **Reveal nothing sensitive or internal**: no secrets or credentials, no
  internal process notes, no internal hostnames or private infrastructure.
- Keep claims **accurate** — don't describe behaviour that isn't shipped.

## Double-check

Before considering a feature "documented," grep each surface for it and confirm
it's actually described (not just incidentally mentioned). A quick coverage
sweep across all five surfaces catches the gaps that a single-file edit misses.
