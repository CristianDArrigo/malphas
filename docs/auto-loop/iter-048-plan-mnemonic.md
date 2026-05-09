# Iter 048 — Plan: BIP39 12-word mnemonic (v0.7.1)

## Problema

Phase 2 (per-user salt) ha aggiunto a "Not protected against": *Loss of
`~/.malphas/salt`*. Senza il file, la stessa passphrase produce
un'identità nuova → tutti i contatti diventano sconosciuti.

L'utente ha chiesto BIP39 mnemonic. Vuole 12 parole, non 24
("24 sono tante").

## Design choice

12 parole BIP39 = **128 bit entropy + 4 bit checksum**. Il nostro salt
è esattamente 16 byte (128 bit), quindi il match è naturale:

```
salt (16 bytes) ↔ 12 BIP39 words
```

La passphrase resta scelta dall'utente (string libera). La mnemonic
**non** rappresenta la passphrase — solo il salt. Ragione:
- L'utente vuole continuare a digitare una passphrase memorizzata
  (l'esempio nel README è "corvo-vetro-martello-1987-luna").
- 12 parole BIP39 random sarebbero più forti come entropia
  (~128 bit vs ~50-60 bit per una buona passphrase) ma di gran lunga
  meno usabili come "qualcosa che memorizzi mentale".
- Il salt invece è 100% random e non c'è nulla da memorizzare → la
  mnemonic è il backup *visibile* di un valore altrimenti opaco.

Workflow risultante:

```
First run, generic:
    malphas
    → genera ~/.malphas/salt random, mostra "your mnemonic: <12 words>"
    → utente trascrive le 12 parole

Recovery on new machine:
    malphas --from-mnemonic "word1 word2 ... word12"
    → decodifica, scrive ~/.malphas/salt
    → (poi prompt passphrase normale)

Show on demand:
    /backup     # CLI command — ristampa la mnemonic del salt corrente
```

## Library

Uso `mnemonic>=0.20` (Trezor python-mnemonic). Implementa BIP39
correttamente con la checksum SHA-256. Wordlist inclusa. Dipendenza
matura, ben mantenuta.

Alternativa scartata: bundle wordlist + checksum in malphas.
~25 KB wordlist + ~30 righe checksum sono nuova superficie di
correttezza che la lib gestisce gratis.

## Implementazione

### `malphas.mnemonic` (nuovo modulo)

```python
def salt_to_mnemonic(salt: bytes) -> str:
    """16-byte salt → 12-word BIP39 mnemonic."""

def mnemonic_to_salt(words: str) -> bytes:
    """12-word BIP39 mnemonic → 16-byte salt. Raises ValueError on
    bad checksum or wrong word count."""
```

### `__main__.py`

- New flag `--from-mnemonic <words>`:
  - decodifica le 12 parole → 16 byte
  - se `~/.malphas/salt` non esiste: scrivilo (mode 0600, atomic).
  - se esiste: confronta; se differisce, errore (l'utente sta
    confondendo due identità diverse — meglio fail-loud).
- After `salt_store.load_or_create_salt`: se il salt è stato
  appena generato (file non esisteva), stampa la mnemonic con un
  warning visivo "save these 12 words now".

### CLI command

`/backup` → ristampa la mnemonic corrente. Utile per recap "where
did I write down my words?"

### Test

`tests/test_mnemonic.py`:
- roundtrip salt→mnemonic→salt
- 12 word count
- invalid mnemonic (checksum) raises ValueError
- wrong-length salt raises
- BIP39 known test vector (taken from trezor-firmware repo or BIP39
  spec) — sanity check we're using English wordlist correctly

## Versioning

Patch 0.7.0 → **0.7.1** (feature additiva non-breaking).

## Out of scope

- Mnemonic non sostituisce la passphrase. La passphrase rimane
  user-supplied stringa.
- Cambio di lingua wordlist (English-only).
- Custom mnemonic length (128 bit / 12 words fissi).
