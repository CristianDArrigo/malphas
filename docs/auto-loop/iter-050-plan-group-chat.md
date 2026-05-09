# Iter 050 — Plan: group chat N-way pairwise (v0.9.0)

## Approccio

Niente MLS, niente group state ratchet condiviso. Il sender cifra il
messaggio una volta per ogni membro del gruppo (fanout pairwise),
sfruttando l'infrastruttura 1-to-1 esistente (sealed sender + auth
prefix + replay cache).

Trade-off:
- pro: stessa security 1-to-1 per ogni copia (sealed sender, replay,
  HMAC/Ed25519 outer auth, onion routing).
- pro: nessun nuovo group key, nessun add/remove member ratchet
  complesso, niente "membership consensus" cross-peer.
- contro: O(N) bytes sul wire per messaggio. Non scala oltre ~50
  membri. Hard cap 50 enforced.
- contro: niente forward secrecy a livello group (ogni copia è
  comunque protetta dal Double Ratchet 1-to-1, ma se un membro è
  compromesso vede il messaggio in chiaro come avveniva prima).

## Wire format

Nuovi kind:

```
group_msg   {kind, from_eph+from_sealed, msg_id, nonce, ts,
             group_id, group_name, members, content}

group_invite {kind, from_eph+from_sealed, msg_id, nonce, ts,
              group_id, group_name, members}
```

`msg_id` è univoco per ogni copia (ricavato con `secrets.token_hex(16)`)
così la replay cache copre senza collisioni.

`members` è la lista completa di peer_id per il display lato
ricevente ("[group X with alice, bob, charlie]").

`group_id` è 16-byte hex random fisso, generato dal creatore.

Backward-compat: 0.8.x e prima dropperanno questi kind (fail-closed
su `_dispatch_kind`).

## Storage

- In-memory only su `MalphasNode._groups`. Wipe on `panic()`.
- Persistenza cross-restart out of scope (potrà essere aggiunta
  all'addressbook in iter futura).

## API

```python
node.create_group(name: str, members: list[str]) -> str
    # ritorna group_id; invia group_invite a ogni member.
node.send_group_message(group_id: str, content: str) -> bool
    # fanout pairwise: per ogni member, _try_send_payload con
    # kind="group_msg".
node.leave_group(group_id: str) -> None
    # rimuove sé stesso dal local registry; NON notifica gli altri
    # (out of scope; loro continueranno a credere che siamo nel
    # gruppo finché non lo capiscono in altro modo).
```

## CLI

- `/group new <name>` → crea gruppo vuoto, group_id stampato.
- `/group add <name> <peer|peer_id>` → aggiunge membro, manda
  group_invite.
- `/group list` → tabella group_id / name / member count.
- `/group leave <name>` → rimuove sé stesso.
- `/group members <name>` → lista peer_id.
- `/chat <group_id|group_name>` → setta active conversation a un
  gruppo (in addition al pattern esistente peer_id|label).
- Quando `active_peer` è un group_id, il `_cmd_send` invoca
  `node.send_group_message` invece di `node.send_message`.

## Test

`tests/test_groups.py`:
- Unit:
  - `Group.add_member` / `remove_member` / `member_count` /
    `member_cap` enforcement.
  - `GroupRegistry.create` / `lookup_by_id` / `lookup_by_name` /
    `wipe`.
- E2E:
  - 3 nodi A/B/C. A crea gruppo, invita B e C. A invia messaggio
    al gruppo. B e C ricevono entrambi.
  - Member cap (50) enforced.
  - Leave rimuove dal registry locale.
  - panic wipes groups.

## Versioning

Minor 0.8.0 → **0.9.0**. Nuova capability significativa.

## Out of scope

- Persistenza dei gruppi cross-restart.
- Add/remove notification ai member esistenti (l'invitato sa, gli
  altri membri non lo sanno).
- Anti-spam / opt-out di group invite.
- Forward secrecy a livello group.
- Member list versioning / consensus.
