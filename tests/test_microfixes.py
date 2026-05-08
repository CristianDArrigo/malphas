"""
Smoke tests for the iter-006 micro-fixes batch:

- A4: secrets-based circuit selection
- A7: reconnect jitter (smoke — no timing assertion)
- A9: monotonic TTL on MessageStore
- C8: identity.py docstring no longer mentions SHA1 in the leading line
"""

import inspect
import time

from malphas import discovery, identity, memory, node

# ── A4: circuit selection uses crypto-strength RNG ────────────────────────────

def test_select_relay_circuit_uses_secrets_systemrandom():
    src = inspect.getsource(discovery.PeerDiscovery.select_relay_circuit)
    # The function body should not import the stdlib `random` directly anymore.
    # Either uses `secrets` or `SystemRandom`.
    assert "secrets" in src
    assert "SystemRandom" in src
    # And it should not use the unsafe `random.sample(` call pattern.
    assert "random.sample(" not in src


# ── A7: reconnect jitter ──────────────────────────────────────────────────────

def test_reconnect_has_jitter():
    src = inspect.getsource(node.MalphasNode._reconnect)
    assert "jitter" in src.lower()
    # Use SystemRandom for jitter as well, not the deterministic stdlib random.
    assert "SystemRandom" in src


# ── A9: monotonic TTL on MessageStore ─────────────────────────────────────────

def test_message_store_uses_monotonic_for_ttl():
    src = inspect.getsource(memory.Message.is_expired)
    assert "monotonic" in src
    src2 = inspect.getsource(memory.MessageStore.store)
    assert "monotonic" in src2


def test_message_store_expiry_with_short_ttl():
    store = memory.MessageStore(ttl_seconds=1, max_messages=10)
    store.store("a", "b", "x", msg_id="id-1")
    assert len(store.get_conversation("a", "b")) == 1
    time.sleep(1.1)
    # purge_expired drops the entry
    removed = store.purge_expired()
    assert removed >= 1
    assert len(store.get_conversation("a", "b")) == 0


# ── C8: identity docstring corrected ─────────────────────────────────────────

def test_identity_module_docstring_mentions_argon2():
    doc = identity.__doc__ or ""
    # The first line should not lead with the obsolete SHA1 description.
    first_line = next((ln for ln in doc.splitlines() if ln.strip()), "")
    assert "SHA1(passphrase)" not in first_line
    assert "Argon2id" in doc
