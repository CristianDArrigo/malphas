# Iter 050 — Green: group chat N-way pairwise (v0.9.0)

## Cosa è stato fatto

### `src/malphas/groups.py` (nuovo)

- Dataclass `Group` con `add_member` / `remove_member` / `member_count`,
  hard cap a `MAX_MEMBERS = 50`.
- `GroupRegistry`: in-memory per-node, lookup by id o name, register
  con name-collision rename (renamed → `<name>#<gid8>`), wipe.

### `src/malphas/node.py`

- 2 nuovi kind: `KIND_GROUP_INVITE` e `KIND_GROUP_MSG`.
- `_groups: GroupRegistry` su `MalphasNode`. `panic()` wipe.
- 4 nuovi handler/API:
  - `_handle_group_invite` — registra il gruppo localmente, notify.
  - `_handle_group_msg` — notify + store in message log con prefix
    `[group X]`.
  - `create_group(name, members)` — registra + fanout `group_invite`.
  - `add_group_member(group_id, peer_id)` — aggiunge + invita.
  - `send_group_message(group_id, content)` — fanout pairwise per
    ogni member ≠ self. Echo locale nello store.
  - `leave_group(group_id)` — rimuove dal local registry only.
- Callback `on_group_invite(cb)` / `on_group_message(cb)`.
- Dispatch in `_dispatch_kind` aggiornato.

### `src/malphas/cli_ui.py`

- Nuovo command `/group <new|list|add|members|leave>`.
- `/chat <group_id|group_name>` ora risolve anche gruppi (group lookup
  prima del peer lookup).
- `_cmd_send` ora dispatcha sul gruppo se `active_peer` è un
  group_id locale.
- Callback `_on_group_invite` (ciano) e `_on_group_message` (formato
  speciale `[group X] alice: msg`).
- Tab completion include `/group`.

### Tests

`tests/test_groups.py` (11 test):
- 7 unit (Group add/cap/remove, GroupRegistry create/lookup/collision/
  rename/wipe).
- 4 E2E (3-node trio in full mesh):
  - create_group_and_invite_distributed
  - group_message_fanout (A → {B, C}, both receive)
  - leave_removes_local_only
  - panic_wipes_groups

Suite focalizzata: 75/75 verde (groups + files + replay + microfixes
+ sealed_sender + salt_store + mnemonic + file_resume).

### CI

- ruff: clean
- mypy strict bucket esteso a 18 moduli (aggiunto `malphas.groups`).
- bandit: 0 findings.

## Note di design

- **Routing constraint emerso**: con tre nodi, l'onion routing in
  malphas richiede che ogni potenziale relay abbia una sessione
  TCP attiva con il next hop. Per il fanout di gruppo questo
  significa "i tre devono essere in mesh" o il routing fallirà
  silenziosamente. Aggiornato il fixture trio per fare full mesh.

- **Multi-receiver replay safety**: ogni copia pairwise ha un
  msg_id univoco (`secrets.token_hex(16)`), così la replay cache
  copre senza collisioni cross-member.

## Versioning

Minor 0.8.0 → **0.9.0**. Wire backward-compatible (kind sconosciuti
sono droppati silenziosamente da 0.8.x e prima).

## Out of scope

- Persistenza dei gruppi cross-restart.
- Add notification ai member esistenti.
- Forward secrecy group-wide.
- Member list versioning / consensus.
