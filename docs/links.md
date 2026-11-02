# Links

**Fleet → Links** is a shared bookmark dashboard: a card grid, grouped by
category, of the web UIs and references your team uses, such as router admin
pages, NAS UIs, wikis and vendor portals. Click anywhere on a card to open it in
a new tab. Ctrl-click and middle-click work too.

## What a link holds

| Field | Notes |
|---|---|
| **Title** | Up to 128 characters. |
| **URL** | `http://` or `https://` only, up to 1,024 characters, no spaces or quotes. Any other scheme, such as `javascript:` or `ftp:`, is refused. |
| **Category** | Up to 64 characters. Pick an existing one or type a new one. Empty means "Uncategorised", which is always listed last. |
| **Scope** | **External** (public internet) or **Internal** (LAN or VPN only). |
| **Description** | Optional, up to 512 characters. Shown under the title and as the tooltip. |

An install holds up to 500 links.

- **Internal** links have a dashed amber border and an **Internal** badge.
  **External** links have a solid accent border and an **External** badge. You
  can tell at a glance whether a link will work from outside the network.
- The filter box matches the title, URL, description and category. The scope
  menu limits the grid to **Internal only** or **External only**.

## Adding and editing

Every signed-in user can see the links. Adding, editing and deleting is
**admin-only** and audited.

- **+ Add link** opens the dialog.
- **Edit mode** adds **Edit** and **Delete** buttons to every card, and stops a
  click from opening the link while you edit. Press **Done editing** when you
  are finished.

## API

| Method & path | Purpose |
|---|---|
| `GET /api/links` | List all links and the set of categories |
| `POST /api/links` | Add a link (admin) |
| `PUT /api/links/{id}` | Replace a link. Send every field (admin) |
| `DELETE /api/links/{id}` | Delete a link (admin) |

## See also

- [Knowledge base](knowledge-base.md): longer notes and runbooks.
- [Contacts](contacts.md): the team phonebook.
