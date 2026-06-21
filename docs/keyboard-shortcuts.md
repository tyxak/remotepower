# Keyboard shortcuts

v3.0.2 adds VI-flavoured keybinds throughout the UI. Press `?` from any page to see the cheat sheet.

## Global

| Key | Action |
|---|---|
| `/` | Open command palette |
| `Ctrl-K` / `Cmd-K` | Open command palette (alternate) |
| `?` | Show this cheat sheet |
| `Esc` | Close any open modal |

The palette searches pages, devices (using the cached list from the Devices page), and quick actions (Bulk actions, Run backup now, Show shortcuts). Arrow keys to navigate, `Enter` to activate.

## Navigation (g-prefix)

Press `g`, then one more key, within 1.5 seconds:

| Sequence | Destination |
|---|---|
| `g h` | Home |
| `g d` | Devices |
| `g l` | Logs |
| `g s` | Settings |
| `g c` | CVEs |
| `g m` | Monitor |
| `g a` | Audit |
| `g r` | Reports |
| `g t` | Trends |
| `g v` | serVer status |

## Implementation notes

- Shortcuts are disabled when any input field, textarea, or contenteditable element has focus — `/` in a search box should be a literal slash, not a palette trigger.
- The palette is also disabled while it's already open; `Esc` is the only way to dismiss.
- The 1.5s window for `g`-prefix shortcuts is short enough that pressing `g` accidentally won't shadow normal typing forever.
- All shortcuts work on macOS via both Ctrl and Cmd modifiers.

## Why VI-flavoured

You said VI over Nano. The single-letter mnemonic prefix matches GitHub, Gmail, GitLab, etc. — `g d` for "go devices" reads naturally and doesn't collide with browser shortcuts.
