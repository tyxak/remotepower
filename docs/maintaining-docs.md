# Keeping the documentation in sync

RemotePower documents the same features in several places, each for a different
reader. When you add, change, or remove a user-facing feature, update **all** of
these in the same change. A feature that lives in the code but not the docs is
effectively invisible, and a half-updated set of docs is worse than none.

## The surfaces (update every one)

1. **A topic guide**, `docs/<topic>.md`. This is where the how-to lives: what the
   feature does, how to use it, its limits and what to do when it misbehaves. Add
   a line for a new guide to the index in `docs/README.md`. A guide that the
   index does not list fails the tests.
2. **The page's Documentation link.** Every page in the app has a
   `Documentation` link to its guide (`<a href="docs/<topic>.md"
   class="c-accent">Documentation</a>`) in a hint line. A new page needs one, and
   a link to a guide that does not exist fails the tests.
3. **The in-app Documentation page**, `Admin → Documentation`
   (`server/html/index.html`). It holds the quick-reference cards and the last
   three "What's new" cards, each with a pointer to the full release notes. Older
   releases are in `CHANGELOG.md`.
4. **README.md**, the project overview and the "What you can do with it" feature
   list.
5. **Release notes**, `docs/vX.Y.Z.md`, for the version that introduces the
   feature. Only the three newest are kept.
6. **"Did you know?" tips**, the `_DYK_TIPS` array in
   `server/html/static/js/app.js`. Add a one-line tip for any feature a user
   would want to discover.
7. **The feature inventory**, `docs/features.md`. It is a tables-only reference
   grouped by topic (Fleet visibility, Alerts, Commands, …). A new feature gets
   **one row** in the matching table. There are no per-version sections, no prose
   and no code blocks. The dated history lives in `CHANGELOG.md`.

`CHANGELOG.md` is separate from these. It is the complete dated history, and it
should be kept current too.

## Tone and content rules

- Write for the **public**, in a natural product voice. Describe what the user
  can do and why it helps, not how it is built inside. Use short sentences and
  speak to the reader as "you".
- A managed machine is a **host**. The word `device` stays only where it is the
  right one: a USB device, a block device, the OAuth device flow, a passkey
  authenticator, and another product's own term. API paths and JSON fields keep
  their spelling (`/api/devices`, `device_id`).
- **Reveal nothing sensitive or internal**: no secrets or credentials, no
  internal process notes, no internal hostnames or private infrastructure.
- Keep claims **accurate**. Do not describe behaviour that is not shipped, and
  check every UI path, button name, setting and number against the product. A
  number that appears in prose goes stale, so leave it out unless a reader needs
  it.
- Keep release narration ("in v4.2 we added…") out of a topic guide. It belongs
  in the release notes and the changelog. Mention a version in a guide only where
  an upgrade needs a compatibility note.

## How the in-app viewer shows a guide

The **Documentation** links open a guide in a window inside the app. The viewer
renders headings, bold and italic text, lists (also nested), tables, code blocks
and quotes. It turns three kinds of link into clickable links: `#heading`
anchors, a guide in the same folder (`other-guide.md` or `other-guide.md#heading`)
and `http(s)` addresses. Any other link target shows as plain text. A single line
break inside a paragraph is wrapping, as on GitHub, so you can wrap lines at a
sensible width.

## Double-check

Before you consider a feature "documented," search each surface for it and
confirm it is described, not just mentioned in passing. The tests catch broken
links, headings that links point to, the host wording, and a few counts. They do
not catch a guide that was never written, so a quick coverage sweep across all
the surfaces is still worth doing.

## See also

- [Documentation index](README.md): every guide, by topic.
- [Features](features.md): the tables-only feature reference.
