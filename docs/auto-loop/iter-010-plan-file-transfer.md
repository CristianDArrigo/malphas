# Iter 010 — Plan: file transfer chunked (red phase)

## Obiettivo

Aggiungere trasferimento file P2P in-memory cifrato end-to-end, riutilizzando
l'onion path esistente, con chunking + dedup + integrità SHA256.

## Wire format extension (backward compatible)

Tre nuovi `kind` nel JSON payload onion-incapsulato:

```
{
  "kind": "file_offer",
  "from": <peer_id>,
  "msg_id": <random hex>,
  "nonce": <random hex>,
  "ts": <unix>,
  "file_id": <random 16-byte hex>,
  "name": <basename>,
  "size": <bytes>,
  "sha256": <64-char hex>,
  "chunk_size": 32768,
  "chunk_count": <N>
}

{
  "kind": "file_chunk",
  "from": <peer_id>,
  "msg_id": <random hex>,
  "nonce": <random hex>,
  "ts": <unix>,
  "file_id": <hex>,
  "chunk_idx": <int 0..N-1>,
  "data_b64": <base64 chunk>
}

{
  "kind": "file_ack",
  "from": <peer_id>,
  "msg_id": <random hex>,
  "nonce": <random hex>,
  "ts": <unix>,
  "file_id": <hex>,
  "status": "accepted" | "rejected" | "completed" | "checksum_mismatch"
}
```

I client vecchi droppano silenziosamente kind sconosciuti (verificare nel
codice esistente che `_deliver_message` faccia early-return su kind ignoti
— se non lo fa, fix incluso).

## Modulo `src/malphas/files.py`

```python
MAX_FILE_BYTES = 100 * 1024 * 1024  # 100 MB
CHUNK_SIZE = 32 * 1024              # 32 KB

@dataclass
class FileOffer:
    file_id: str
    name: str
    size: int
    sha256: str
    chunk_size: int
    chunk_count: int

class OutgoingFile:
    """Held by the sender. chunkify yields (idx, data) pairs."""
    def __init__(self, path: str): ...
    def offer(self) -> FileOffer: ...
    def chunkify(self) -> Iterator[tuple[int, bytes]]: ...

class IncomingFile:
    """Held by the receiver."""
    def __init__(self, offer: FileOffer): ...
    def add_chunk(self, idx: int, data: bytes) -> bool:
        # Returns True if the file is now complete.
    def is_complete(self) -> bool: ...
    def assemble(self) -> bytes: ...   # raises ValueError on integrity fail
    def progress(self) -> float: ...   # 0.0..1.0
    def cancel(self) -> None: ...      # frees memory

class FileTransferManager:
    """Per-node coordinator: handles outgoing/incoming registry."""
    def __init__(self, max_concurrent: int = 8): ...
    def register_outgoing(self, of: OutgoingFile) -> str: ...
    def register_incoming(self, offer: FileOffer) -> IncomingFile: ...
    def get_incoming(self, file_id: str) -> IncomingFile | None: ...
    def cancel(self, file_id: str) -> None: ...
    def wipe(self) -> None: ...
```

## Integrazione node.py

- `MalphasNode.__init__` aggiunge `self._files = FileTransferManager()`.
- `_deliver_message` scarta kind sconosciuti senza warning (già il caso oggi
  per `KIND_COVER`; aggiungere `file_offer/chunk/ack` come dispatch).
- Nuovo metodo pubblico `send_file(dest_peer_id, path) -> str | None` che
  ritorna il `file_id` o None se peer offline / file troppo grande.
- Callback `on_file_offer(callback)` invocato quando arriva un `file_offer`.
- `panic()` chiama `self._files.wipe()`.

## CLI

- `/sendfile <peer|label> <path>` — sender side.
- Notifica receiver con `file_id` per accept/reject.
- `/accept <file_id>` / `/reject <file_id>`.
- Quando completo: notifica con il payload (in RAM); per ora `/savefile <file_id> <path>`
  per salvare su disco esplicito.

## Test plan (TDD red)

`tests/test_files.py`:

### Unit (no rete)

1. `test_outgoing_chunkify_count_matches_size` — file 100 KB / chunk 32KB → 4 chunks.
2. `test_outgoing_offer_sha256_correct`.
3. `test_incoming_assemble_byte_perfect`.
4. `test_incoming_chunk_dedup` — stesso `(file_id, idx)` due volte non corrompe.
5. `test_incoming_chunk_out_of_order` — chunk 2,0,1,3 si ricostruiscono uguali.
6. `test_incoming_sha256_mismatch_raises`.
7. `test_max_file_size_enforced_sender` — file 200 MB → errore.
8. `test_max_file_size_enforced_receiver` — offer.size > MAX → reject.
9. `test_cancel_frees_memory` — `cancel()` svuota i chunk buffer.
10. `test_progress_reports_correct_fraction`.

### Integration (E2E con node)

11. `test_send_file_small_arrives_intact` — A→B 1 KB.
12. `test_send_file_medium_arrives_intact` — A→B 100 KB.
13. `test_send_file_large_arrives_intact` — A→B 1 MB.
14. `test_unknown_file_id_chunks_dropped` — bogus `file_id` → drop.
15. `test_panic_wipes_files`.

## Estimate

- 2 iterazioni red/green (red: test, green: impl).
- Modifiche code: ~300-400 LOC tra `files.py` + integration.
- Test: ~250 LOC.

## Versioning

Minor 0.2.x → 0.3.0 perché aggiunge un nuovo capability sostanziale, anche
se backward-compatible. Bump motivato dal cambio del README "what malphas
can do".

## Non in scope

- Salvataggio automatico su disco (solo `/savefile` esplicito).
- Resume di file interrotti.
- Compressione.
- Cifratura aggiuntiva (già il messaggio è cifrato dall'onion).
- File grandi >100 MB.
