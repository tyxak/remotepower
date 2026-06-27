# Internal contact directory

The **Contacts** page (under **Admin** in the sidebar) is a small, shared
phonebook for your team — the people you call when something breaks: the on-call
network admin, a vendor's support line, the data-centre's remote hands, a
customer's IT contact.

It is deliberately separate from the [ticket system](ticket-system.md): contacts
are reference information, not work items, and the page is available whether or
not the ticket system is enabled.

## What's in a contact

| Field | Notes |
| --- | --- |
| **Name** | Required. |
| **Role** | e.g. *Network admin*, *On-call*, *Vendor support*. |
| **Company / team** | The organisation or internal team. |
| **Email** | Click to start a message. |
| **Phone** | Click to dial on a device that supports `tel:` links. |
| **Notes** | Anything else worth remembering. |

## Using it

- The list is **searchable** (name, role, company, email, phone) and **sortable**
  on every column.
- Everyone can view and search the directory; **adding, editing and deleting**
  contacts are admin actions, so the list stays curated.
- Email and phone values render as clickable `mailto:` / `tel:` links.

Everything is stored on your own server alongside the rest of RemotePower's state —
no external address-book service is involved.

See also: [Built-in ticket system](ticket-system.md) · [CMDB & documentation](cmdb.md).
