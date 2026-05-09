# Iter 051 — Plan: Tkinter GUI (v0.10.0)

## Constraint utente

> "tkinter sarebbe carino ma fatto bene"

"Fatto bene" qui significa:
- ttk styled, niente look-and-feel Win98.
- asyncio/Tk bridge che non blocca né uno né l'altro.
- UI funzionale per i flow primari (chat 1-to-1, file transfer,
  group chat, backup/restore, panic).
- Nessun spinner finto.
- Cleanup pulito su quit (node.stop, asyncio loop stop, Tk destroy).

## Architettura

```
┌─────────────── Tk thread (main) ───────────────┐
│  MalphasGUI                                     │
│  ├── menubar (File / View / Help)               │
│  ├── PanedWindow                                │
│  │   ├── sidebar: peers + groups treeview       │
│  │   └── main: chat history + input             │
│  └── status bar                                 │
│                                                  │
│  drain queue every 50 ms (root.after(50, …))    │
└─────────────────────────────────────────────────┘
                ▲       ▼  queue.Queue
                │       │  (events from node)
┌─────────────── asyncio thread ─────────────────┐
│  MalphasNode running in its own event loop     │
│  Callbacks push events into queue              │
│  Send actions: bridge.submit_coro(...)         │
└─────────────────────────────────────────────────┘
```

`AsyncBridge` runs `asyncio.new_event_loop()` in a daemon thread,
exposes `submit_coro(coro)` to schedule from the Tk thread, and
`stop()` to shut down. Node lifecycle (start, callback register,
stop) happens **inside** the asyncio loop via submitted coroutines.

## Flow di avvio

1. Passphrase prompt via terminal (`getpass.getpass`). The same
   interactive shell that launches `malphas --mode gui`.
2. Resolve the per-user salt + identity (same flow as CLI/web).
3. Construct the node + bridge; submit `node.start()`.
4. Auto-connect address book entries via `bridge.submit_coro`.
5. `MalphasGUI(node, book, bridge, salt_path).run()` blocks on
   `mainloop()`.
6. On window-close: `bridge.submit_coro(node.stop())`, wait,
   `bridge.stop()`, `root.destroy()`.

## UI breakdown

### Menubar

- **File**: New invite (clipboard) | Import invite | Backup mnemonic | Quit
- **View**: Refresh peers
- **Help**: About | GitHub

### Sidebar (left, ~220px)

`ttk.Treeview` with two top-level groups:

```
PEERS
  alice (a0f8…)
  bob   (b3c4…)

GROUPS
  fellowship (3 members)
  council    (5 members)
```

Click switches active conversation.

### Main pane

- Top: read-only `tk.Text` with chat scrollback. Tagged styles for
  `you:`, `peer:`, system messages, file offers.
- Below: `ttk.Entry` for input + a "send file" button that opens a
  `filedialog.askopenfilename`.

### Status bar

`<peers count> peers   |   <active conversation>   |   <onion if tor>`

### Events

| Node callback | What we do |
|---------------|------------|
| `on_message(from, content)` | Append to chat for active==from, else flash sidebar |
| `on_receipt(msg_id, dest, ok)` | Inline ✓/✗ next to sent line |
| `on_pin_violation(...)` | Modal dialog "key changed!" |
| `on_file_offer(from, offer)` | Modal: Accept / Reject / Save-to (later) |
| `on_file_complete(file_id, data)` | Modal: Save-as filedialog |
| `on_group_invite(from, gid, gname, members)` | Sidebar refresh + status flash |
| `on_group_message(from, gid, gname, content)` | Like on_message but [group X] prefix |

## Module layout

`src/malphas/gui.py`:
- `class AsyncBridge`
- `class MalphasGUI`
- `def launch_gui(node, book, salt_path)` — entry point called by
  `__main__.py` when `--mode gui`.

`__main__.py`:
- Add `gui` to the `--mode` choices.
- New `_run_gui(args)` async-bootstrap function that resolves
  passphrase + salt + identity, spins the node + bridge, hands
  off to `launch_gui()`.

## Test plan

- Smoke unit: instantiate `MalphasGUI` with a mock node, assert that
  `_build_ui()` doesn't crash and the menubar is wired.
- `AsyncBridge` lifecycle: start → submit_coro returns a Future →
  result available → stop is clean.
- The Tk mainloop is **not** entered in tests (would block).

Tkinter GUI behavior is hard to E2E test without Xvfb. Out of scope
for this iter — relying on the asyncio bridge pattern being well-known
and the Tk widgets being stdlib-stable.

## Versioning

Minor 0.9.0 → **0.10.0**. New capability + new entry mode. No wire
change.

## Out of scope

- Drag-and-drop file send.
- Notification system / system tray.
- Multi-window.
- Theme switcher (the theme is fixed dark-ish).
- Custom font loading.
- i18n.
