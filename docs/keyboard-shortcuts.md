# Keyboard shortcuts

RemotePower has VI-flavoured shortcuts throughout the UI. Press `?` from any page to see the cheat sheet. It lists the shortcuts below, and adds a **This page** section with the keys of the page you are on and a link to its guide.

## Global

| Key | Action |
|---|---|
| `/` | Open the command palette |
| `Ctrl-K` / `Cmd-K` | Open the command palette (alternate) |
| `?` | Show the cheat sheet |
| `Ctrl-Z` / `Cmd-Z` | Undo the last undoable change (the arrows in the top bar). Add `Shift` to redo. |
| `Ctrl-Enter` / `Cmd-Enter` | Press the main button of the open dialog |
| `Esc` | Close the open dialog, menu or palette |

Right-click the undo arrow in the top bar to see the whole undo history and step back to any entry.

## The command palette

The palette is a quick way to jump somewhere or run an action. Type to filter, use the arrow keys to move and `Enter` to open the highlighted row. It searches:

- every page in the sidebar (a page that is switched off is not listed);
- your hosts, with pinned and recently viewed hosts first (pin one with the star in the host drawer), and each host's timeline;
- actions: Bulk actions, Keyboard shortcuts, Run backup now and Download fleet report (JSON);
- per-host actions for hosts with an agent: run a command, open the web terminal, reboot and shut down. Reboot and shut down still ask you to confirm;
- saved scripts (after you have visited the Scripts page), open alerts, CVE findings and your recent commands;
- the knowledge index (tickets, KB articles, CMDB entries, contacts and the docs), from three typed characters on, when it is switched on under **Settings → AI assistant → Knowledge index (RAG)**. These rows arrive a moment after the local ones.

Start the query with `>` to see actions only, or with `#` to see hosts only.

## Navigation (g-prefix)

Press `g`, then one more key, within 1.5 seconds:

| Sequence | Destination |
|---|---|
| `g h` | Dashboard |
| `g d` | Hosts |
| `g l` | Logs |
| `g s` | Settings |
| `g c` | CVEs |
| `g m` | Live Monitor |
| `g a` | Audit |
| `g r` | Reports |
| `g t` | Trends |
| `g v` | serVer status |

## On the Alerts page

| Key | Action |
|---|---|
| `j` / `k` | Move the selection down / up |
| `a` | Acknowledge (you can undo it) |
| `r` | Resolve |
| `m` | Mute |
| `x` | Tick or untick the row |
| `Esc` | Clear the selection |
| `?` | Show these keys in a toast |

See [Alerts](alerts.md) for what each action does.

## Other keys

- With the host drawer open, `]` steps to the next host and `[` to the previous one.
- On the Hosts page, `Esc` clears the selection when no dialog or drawer is open.
- `Esc` leaves kiosk mode and the alert wall.
- In a row of tabs, such as the Settings tabs, the arrow keys move between tabs.
- In the sidebar search box, `Enter` opens the first hit and `Esc` clears the box.
- On a clickable row or card that is not a native button or link, `Enter` or `Space` presses it.

## Dialogs, menus and the host drawer

They all work the same way, so you learn them once:

- A dialog opens with focus on its first field or button, and `Tab` and `Shift-Tab` stay inside it.
- `Esc` closes the one on top and puts focus back on the button you used to open it. A prompt that opens from a dialog (the "type RUN" prompt of a bulk reboot) closes first; a second `Esc` closes the dialog under it.
- `Ctrl-Enter` presses the dialog's main button.
- The same holds for Bulk actions, the cheat sheet, the first-run tour, the notification list and the host drawer.
- Rows that open something, such as the activity feed on Home and the dots on the Sites map, can be reached with `Tab` and opened with `Enter`.

## Good to know

- Shortcuts are off while an input field, textarea or editable element has focus, so `/` in a search box is a literal slash and not a palette trigger.
- The palette ignores the other shortcuts while it is open. `Esc` closes it.
- The 1.5 second window for `g` shortcuts is short enough that pressing `g` by accident does not shadow your typing for long.
- On macOS, `Cmd` works wherever `Ctrl` does.

## Why VI-flavoured

A single-letter prefix is quick to type, matches GitHub, Gmail and GitLab, and does not collide with browser shortcuts. `g d` still opens the host list: the `d` is left over from when that page was called Devices, and the key stays so nobody has to relearn it.

## See also

- [Finding your way around](navigation.md): the sidebar, the command palette and the All pages map.
- [Accessibility](accessibility.md): keyboard support across the UI.
