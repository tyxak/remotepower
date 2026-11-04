# Knowledge base: IT documentation

The **Knowledge base** (**Business → Knowledge base**) is a store of
operator-authored documentation: standard operating procedures, how-tos and
runbooks, written in **Markdown** and organised in a category folder tree.

It is off by default. Switch it on under **Settings → Advanced → Optional
modules → Knowledge base**. The sidebar entry appears once it is on, and while
it is off the whole `/api/kb` API answers not found.

## Articles

Each article has a **title** (up to 200 characters), a **category** (a
path-like folder such as `network/vpn`, up to eight levels deep), optional
**tags** (up to 24), a **Pin to the top of the list** flag, and a Markdown
**body** of up to 100,000 characters. An install holds up to 5,000 articles.

The list on the left groups articles by category. Pinned articles float to a
**Pinned** group, marked with a star, at the top. The search box above it filters the list by title,
category and tags. Click an article to read it on the right. The article view
renders headings, bold and italic text, lists, tables, code blocks and quotes.
It shows a Markdown link as plain text, so write out an address in full where a
reader needs to copy it. For clickable bookmarks, use [Links](links.md).

While you write, the editor keeps a draft in your browser. If you close the
dialog before saving, opening the editor again offers **Restore draft**.

Creating, editing and deleting articles is **admin-only** and audited. **All
signed-in roles can read** the knowledge base.

## Fed to the AI assistant (RAG)

The knowledge base is a **RAG source**, on by default once the KB is enabled.
Each article becomes a retrievable document, so the AI assistant can ground its
answers in *your own* documentation. Ask "how do we rotate the VPN keys?" and
it can answer from the runbook you wrote, with a citation. Switch the source on
or off under **Settings → AI assistant → Knowledge index (RAG)**. The command
palette searches the same index, so `Ctrl-K` finds an article by what it says
(see [Keyboard shortcuts](keyboard-shortcuts.md#the-command-palette)).

## Runbook links on alerts

The KB page's **Runbook links** card maps an **alert type** to an article. Pick
the type, pick the article and press **Link runbook**. When an alert of that
type appears in the Alerts inbox, operators get a one-click **Runbook** link on
the alert row, straight to your response procedure, so the fix instructions
live next to the alarm. **Unlink** removes a link.

The card lists the alert types you can notify on. A link works for any of them,
and you can also map a specific custom check by setting `check:<check id>` in
`alert_runbooks` through `POST /api/config`. The mapping is stored in the
config (`alert_runbooks`) and resolved when the inbox is read. Nothing is
copied onto the alert, so editing an article always shows the current version.
Links only appear while the KB is enabled, and only admins see the card.

## API

| Method & path | Purpose |
| --- | --- |
| `GET /api/kb[?q=&category=]` | List and search articles (metadata only). `q` also searches the body. The answer includes the list of categories. |
| `POST /api/kb` | Create an article (admin) |
| `GET /api/kb/{id}` | Read one article (full body) |
| `PATCH /api/kb/{id}` | Update an article (admin) |
| `DELETE /api/kb/{id}` | Delete an article (admin) |

Articles are stored in `kb.json`. Empty, `.` and `..` segments are dropped from a
category path before it is saved. Create and update also accept `linked_devices`, a list
of up to 50 host ids. The page has no field for it, and a reader only ever sees the
linked hosts they are allowed to see.

## With multi-tenancy

The articles are one library for every tenant. Everyone can read them, but an article lists only the hosts the reader can see, and only the platform operator can add, change or delete articles.

## See also

- [AI assistant](ai.md): how the knowledge index is built and what is sent to a provider.
- [Alerts](alerts.md): the inbox the runbook links appear in.
- [Links](links.md): shared bookmarks.
