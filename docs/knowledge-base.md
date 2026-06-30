# Knowledge base — IT documentation

*(v5.6.0 "ProvisionMatters")*

The **Knowledge base** (Admin → Knowledge base) is an opt-in store of
operator-authored documentation: standard operating procedures, how-tos and
runbooks, written in **Markdown** and organised in a category folder tree.

Enable it under **Settings → Advanced → Optional features → Knowledge base**.
The sidebar entry appears once it's on.

## Articles

Each article has a **title**, a **category** (a path-like folder, e.g.
`network/vpn`), optional **tags**, an optional **pinned** flag, and a Markdown
**body**. The list on the left groups articles by category (pinned ones float to
a "★ Pinned" group at the top) and a search box filters across title, category,
tags and body. Click an article to read the rendered Markdown on the right.

Creating, editing and deleting articles is **admin-only** and audited; **all
signed-in roles can read** the knowledge base.

## Fed to the AI assistant (RAG)

The knowledge base is wired in as a **RAG source** (on by default once the KB is
enabled). Each article becomes a retrievable document, so the AI assistant can
ground its answers in *your own* documentation — ask "how do we rotate the VPN
keys?" and it can answer from the runbook you wrote, with a citation. Toggle the
source under **Settings → AI → Knowledge sources**.

## API

| Method & path | Purpose |
| --- | --- |
| `GET /api/kb[?q=&category=]` | List / search articles (metadata only) |
| `POST /api/kb` | Create an article (admin) |
| `GET /api/kb/{id}` | Read one article (full body) |
| `PATCH /api/kb/{id}` | Update an article (admin) |
| `DELETE /api/kb/{id}` | Delete an article (admin) |

Articles are stored in `kb.json`. Category paths are normalised and
traversal-guarded; the body is capped at 100 KB.
