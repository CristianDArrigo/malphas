# Iter 051 — Green: Tkinter GUI (v0.10.0)

## Cosa è stato fatto

### `src/malphas/gui.py` (~530 righe)

Tre componenti:

#### `AsyncBridge`

- Avvia un nuovo `asyncio.new_event_loop()` su un daemon thread.
- `submit_coro(coro)` ritorna un `concurrent.futures.Future` che il
  Tk thread può `.result(timeout=)` o ignorare.
- `stop(timeout)` chiama `loop.call_soon_threadsafe(loop.stop)` e
  joina il thread.

#### `MalphasGUI`

- ttk-styled dark theme: BG `#1a1a1a`, FG `#e0e0e0`, ACCENT `#c83232`.
- Layout `PanedWindow` orizzontale: sidebar (treeview "PEERS / GROUPS")
  + main pane (chat Text + Entry + send + 📎 file).
- Status bar con `<peers count> | chat: <active> | tor` (auto-refresh
  ogni 1 s).
- Menubar:
  - **File**: Generate invite (clipboard) | Import invite from clipboard
    | Backup mnemonic | PANIC | Quit.
  - **View**: Refresh peer list.
  - **Group**: Create new group | Add member | Leave active group.
  - **Help**: About | Open GitHub.
- `event_queue: queue.Queue` raccoglie i callback dal node (asyncio
  thread); `_drain_events()` viene richiamato ogni 50 ms con
  `root.after(50, …)` e processa al massimo 50 eventi per tick così
  non blocca il mainloop.
- Per-conversation scrollback in `_scrollback` dict: passare da una
  conversazione all'altra non perde la cronologia (in-RAM).

#### `launch_gui(node, book, bridge, salt_path)`

Costruisce la GUI ed entra nel mainloop. Ritorna quando l'utente
chiude o panic.

### Modifiche `__main__.py`

- `--mode {cli,web,gui}`. Default cli.
- Nuovo `_run_gui(args)` sincrono: prompt passphrase su terminale
  (riusa la `getpass`), risolve salt+identity (stesso flow di
  CLI/web), istanzia `AsyncBridge`, fa `bridge.submit_coro(node.start())
  .result(10s)`, lancia `launch_gui(...)`. Cleanup teardown su quit.

### Test

`tests/test_gui.py` (7 test):
- AsyncBridge: starts and stops, submits a coroutine and gets the
  result, two independent calls don't collide, submit-after-stop
  raises (or fails predictably).
- Helpers: `_short` truncates, `_ts` returns HH:MM.
- GUI construction: `MalphasGUI(...)` con un node mock costruisce
  la widget tree senza crashare e si chiude pulito (gated by
  DISPLAY env var).

7/7 verde su un sistema con DISPLAY (Xorg/Wayland). Su CI headless
il test `test_gui_constructs_without_running_mainloop` viene
skippato; gli altri girano comunque.

### Bucket strict

`malphas.gui` aggiunto al **lenient** bucket. Le annotazioni di
tkinter sono incomplete e i Tcl variables (StringVar, IntVar)
producono falsi positivi sotto strict — l'investimento per
strict non vale per un UI module.

## Verifica gates

- ruff: clean.
- mypy: 25 file totali, di cui 18 strict + 7 lenient (incluso `gui`).
- bandit: 0 findings.
- 82/82 verde su sotto-suite focalizzata.

## Versioning

Minor 0.9.0 → **0.10.0**. Wire format invariato — la GUI è solo una
nuova superficie di presentazione sopra l'API esistente del node.

## Note di "fatto bene"

L'utente ha chiesto "tkinter ma fatto bene". Le scelte di "non-cheap":
- Asyncio/Tk separation — niente `update_idletasks()` in loop, niente
  `time.sleep()` nel main thread.
- Per-conversation scrollback non si perde quando l'utente cambia chat.
- ttk theme custom (clam + colori) — non sembra Win98.
- Message dispatch tagged in `tk.Text` (you/them/ts/system/group/ok)
  con colori distintivi.
- Menu Group + File + View + Help logicamente raggruppati.
- Status bar dinamica.
- PANIC esplicito dal menu (con confirm dialog).
- Mnemonic backup in dialog — formato a due colonne di 6 parole.
- file send/receive integrati con filedialog standard.
- Auto-connect address book on launch.
- Cleanup pulito: WM_DELETE_WINDOW → node.stop → bridge.stop → root.destroy.

## Out of scope (consapevolmente)

- Drag-and-drop file send.
- Tray / notifications.
- Multi-window.
- Theme switcher.
- Custom font loading.
- i18n.
