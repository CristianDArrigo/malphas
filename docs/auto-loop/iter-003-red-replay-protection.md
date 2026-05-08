# Iter 003 — TDD Red: replay protection failing tests

## Cosa è stato fatto

Creato `tests/test_replay_protection.py` con due gruppi:

1. **Unit `TestReplayCacheUnit`** (8 test) — verifica direttamente `ReplayCache`:
   - first_insert_returns_false
   - second_insert_returns_true
   - distinct_msg_ids_independent
   - distinct_senders_independent
   - ttl_expiry
   - cap_evicts_oldest
   - wipe_clears_everything
   - purge_expired_returns_count

2. **Integration `TestReplayIntegration`** (6 test) — su nodi reali:
   - test_ratchet_path_replay_is_dropped
   - test_hmac_path_replay_is_dropped (forza fallback annullando `conn.ratchet`)
   - test_ed25519_path_replay_is_dropped (annulla anche `conn.hmac_key`)
   - test_distinct_msg_ids_both_delivered
   - test_panic_wipes_replay_cache (verifica `b._replay`)
   - test_message_store_no_double_entry

## Perché questa selezione

I test seguono direttamente gli acceptance criteria di iter-002. Hanno dipendenze chiare:

- I test integration usano `_try_send(dest, content, msg_id)` con msg_id forzato, sfruttando l'API interna esistente. Niente cambi di firma pubblica.
- I path HMAC/Ed25519 sono forzati azzerando `ratchet` (e `hmac_key` per Ed25519) sulle connection sia sender che receiver — corrisponde al comportamento storico se la ratchet non è ancora pronta o è stata wiped.
- Il test `test_panic_wipes_replay_cache` controlla `b._replay` direttamente: questo dichiara la API interna del nodo (`self._replay: ReplayCache`).

## Stato atteso (red)

- Tutti i test devono fallire all'import: `from malphas.replay import ReplayCache` → `ModuleNotFoundError`.
- Non eseguo `pytest` ora perché non ci sono ancora il modulo né l'integrazione: il "red" è dichiarativo — è impossibile che passi prima dell'iter 004.

Verifica empirica del red verrà fatta runando `pytest tests/test_replay_protection.py -x` dopo l'iter 004 per assicurarsi che senza l'integrazione i test falliscano. (Lo facciamo a posteriori aggiungendo un commit "red verification" o lo ignoriamo, dato che l'integrazione è atomica con il modulo.)

## Note

- Nessun cambio in altri file di test esistenti.
- Le porte 18101/18102 sono nuove rispetto al pool esistente (17777, 17778, 18001..18005) — niente collisioni.
- I test sono `asyncio_mode=auto` compatibili (no `@pytest.mark.asyncio` necessario).
