# Keyboard shortcuts

v3.0.2 adds VI-flavoured keybinds throughout the UI. Press `?` from any page to see the cheat sheet.

## Global

| Key | Action |
|---|---|
| `/` | Open command palette |
| `Ctrl-K` / `Cmd-K` | Open command palette (alternate) |
| `?` | Show this cheat sheet |
| `Esc` | Close any open modal |

The palette searches pages, hosts (using the cached list from the Hosts page), and quick actions (Bulk actions, Run backup now, Show shortcuts). Arrow keys to navigate, `Enter` to activate.

## Navigation (g-prefix)

Press `g`, then one more key, within 1.5 seconds:

| Sequence | Destination |
|---|---|
| `g h` | Home |
| `g d` | Hosts |
| `g l` | Logs |
| `g s` | Settings |
| `g c` | CVEs |
| `g m` | Monitor |
| `g a` | Audit |
| `g r` | Reports |
| `g t` | Trends |
| `g v` | serVer status |

## Dialogs, menus and the host drawer

They all work the same way, so you learn them once:

- A dialog opens with focus on its first field or button, and `Tab` and `Shift-Tab` stay inside it.
- `Esc` closes the one on top and puts focus back on the button you used to open it. A prompt that opens from a dialog (the "type RUN" prompt of a bulk reboot) closes first; a second `Esc` closes the dialog under it.
- `Ctrl-Enter` presses the dialog's main button.
- The same holds for Bulk actions, this cheat sheet, the first-run tour, the notification list and the host drawer.
- Rows that open something, such as the activity feed on Home and the dots on the Sites map, can be reached with `Tab` and opened with `Enter`.

## Implementation notes

- Shortcuts are disabled when any input field, textarea, or contenteditable element has focus — `/` in a search box should be a literal slash, not a palette trigger.
- The palette is also disabled while it's already open; `Esc` is the only way to dismiss.
- The 1.5s window for `g`-prefix shortcuts is short enough that pressing `g` accidentally won't shadow normal typing forever.
- All shortcuts work on macOS via both Ctrl and Cmd modifiers.

## Why VI-flavoured

You said VI over Nano. The single-letter mnemonic prefix matches GitHub, Gmail, GitLab, etc. and doesn't collide with browser shortcuts. `g d` still opens the host list: the `d` is left over from when that page was called Devices, and the key stays so nobody has to relearn it.
