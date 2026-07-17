"""
X3DH prekey key-agreement tests (issue #12).

X3DH lets a sender establish a forward-secret, deniable session with a peer it
is not interactively connected to (multi-hop delivery), using the peer's
published signed prekey. Both sides must derive the same shared secret.
"""
import asyncio
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from malphas.prekey import (
    generate_signed_prekey,
    verify_signed_prekey,
    x3dh_initiator,
    x3dh_responder,
)


def _x25519():
    p = X25519PrivateKey.generate()
    return p, p.public_key().public_bytes_raw()


def test_signed_prekey_verifies():
    ed = Ed25519PrivateKey.generate()
    ed_pub = ed.public_key().public_bytes_raw()
    spk_priv, spk_pub, spk_sig = generate_signed_prekey(ed)
    assert verify_signed_prekey(spk_pub, spk_sig, ed_pub)
    # Tampered prekey fails.
    assert not verify_signed_prekey(bytes(32), spk_sig, ed_pub)
    # Wrong signer fails.
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    assert not verify_signed_prekey(spk_pub, spk_sig, other)


def test_initiator_and_responder_derive_same_secret():
    # Bob (responder) identity + signed prekey.
    ik_b_priv, ik_b_pub = _x25519()
    spk_b_priv, spk_b_pub, _sig = generate_signed_prekey(Ed25519PrivateKey.generate())
    # Alice (initiator) identity.
    ik_a_priv, ik_a_pub = _x25519()

    sk_a, ek_a_pub = x3dh_initiator(ik_a_priv, ik_b_pub, spk_b_pub)
    sk_b = x3dh_responder(ik_b_priv, spk_b_priv, ik_a_pub, ek_a_pub)

    assert sk_a == sk_b
    assert len(sk_a) == 32


def test_different_sessions_yield_different_secrets():
    ik_b_priv, ik_b_pub = _x25519()
    spk_b_priv, spk_b_pub, _ = generate_signed_prekey(Ed25519PrivateKey.generate())
    ik_a_priv, ik_a_pub = _x25519()

    sk1, _ = x3dh_initiator(ik_a_priv, ik_b_pub, spk_b_pub)
    sk2, _ = x3dh_initiator(ik_a_priv, ik_b_pub, spk_b_pub)
    # Fresh ephemeral each call -> different session key (forward secrecy).
    assert sk1 != sk2


def test_wrong_responder_key_fails_to_match():
    ik_b_priv, ik_b_pub = _x25519()
    spk_b_priv, spk_b_pub, _ = generate_signed_prekey(Ed25519PrivateKey.generate())
    ik_a_priv, ik_a_pub = _x25519()
    sk_a, ek_a_pub = x3dh_initiator(ik_a_priv, ik_b_pub, spk_b_pub)

    # An attacker with a different identity key cannot derive the same secret.
    wrong_ik_priv, _ = _x25519()
    sk_wrong = x3dh_responder(wrong_ik_priv, spk_b_priv, ik_a_pub, ek_a_pub)
    assert sk_wrong != sk_a


def test_x3dh_seeds_ratchet_roundtrip():
    """The X3DH shared secret must seed a Double Ratchet that both sides agree on."""
    from malphas.ratchet import RatchetState

    ik_b_priv, ik_b_pub = _x25519()
    spk_b_priv, spk_b_pub, _ = generate_signed_prekey(Ed25519PrivateKey.generate())
    ik_a_priv, ik_a_pub = _x25519()

    sk_a, ek_a_pub = x3dh_initiator(ik_a_priv, ik_b_pub, spk_b_pub)
    sk_b = x3dh_responder(ik_b_priv, spk_b_priv, ik_a_pub, ek_a_pub)
    assert sk_a == sk_b

    # Alice seeds as initiator, using Bob's SPK as the initial ratchet key.
    r_a = RatchetState.from_shared_secret(
        sk_a, our_dh_priv=X25519PrivateKey.generate(),
        remote_dh_pub=spk_b_pub, is_initiator=True)
    header, ct = r_a.encrypt(b"secret over multi-hop")

    # Bob seeds as responder, using his SPK private as the initial ratchet key.
    r_b = RatchetState.from_shared_secret(
        sk_b, our_dh_priv=spk_b_priv,
        remote_dh_pub=spk_b_pub, is_initiator=False)
    assert r_b.decrypt(header, ct) == b"secret over multi-hop"


async def test_x3dh_forward_secret_delivery_over_fallback(identity_a, identity_b):
    """A message to a peer we know the SPK for (but are not connected to) is
    delivered via a forward-secret X3DH session, not the plaintext fallback."""
    from malphas.node import MalphasNode
    from malphas.obfuscation import pad_payload
    from malphas.sealed_sender import seal as seal_from

    node_a = MalphasNode(identity_a, "127.0.0.1", 17790, cover_traffic=False)
    node_b = MalphasNode(identity_b, "127.0.0.1", 17791, cover_traffic=False)

    # A knows B including B's signed prekey; B knows A (for the sender binding).
    node_a.discovery.add_peer(
        identity_b.peer_id, "127.0.0.1", 17791,
        identity_b.x25519_pub_bytes, identity_b.ed25519_pub_bytes,
        spk_pub=node_b.signed_prekey_pub)
    node_b.discovery.add_peer(
        identity_a.peer_id, "127.0.0.1", 17790,
        identity_a.x25519_pub_bytes, identity_a.ed25519_pub_bytes)

    got = []
    node_b.on_message(lambda frm, content: got.append((frm, content)))

    dest_peer = node_a.discovery.get_peer(identity_b.peer_id)
    from_eph, from_sealed = seal_from(identity_a.peer_id, identity_b.x25519_pub_bytes)
    payload = json.dumps({
        "kind": "msg", "from_eph": from_eph, "from_sealed": from_sealed,
        "content": "multi-hop secret", "msg_id": "m1",
        "nonce": "00" * 16, "ts": int(time.time()),
    }).encode()

    wrapped = node_a._wrap_for_dest(payload, identity_b.peer_id, dest_peer)
    # Must use the forward-secret X3DH opener, NOT the non-deniable Ed25519 fallback.
    assert wrapped[0:1] == b"X"

    await node_b._deliver(pad_payload(wrapped))
    await asyncio.sleep(0.05)
    assert any(c == "multi-hop secret" for _f, c in got)

    # A second message advances the ratchet (AUTH_RATCHET, session established).
    payload2 = json.dumps({
        "kind": "msg", "from_eph": from_eph, "from_sealed": from_sealed,
        "content": "second", "msg_id": "m2",
        "nonce": "11" * 16, "ts": int(time.time()),
    }).encode()
    wrapped2 = node_a._wrap_for_dest(payload2, identity_b.peer_id, dest_peer)
    assert wrapped2[0:1] == b"R"  # ratchet, not a fresh X3DH opener
    await node_b._deliver(pad_payload(wrapped2))
    await asyncio.sleep(0.05)
    assert any(c == "second" for _f, c in got)


def test_x3dh_with_one_time_prekey_agrees_and_differs():
    ik_b_priv, ik_b_pub = _x25519()
    spk_b_priv, spk_b_pub, _ = generate_signed_prekey(Ed25519PrivateKey.generate())
    opk_b_priv, opk_b_pub = _x25519()
    ik_a_priv, ik_a_pub = _x25519()

    sk_a, ek_a = x3dh_initiator(ik_a_priv, ik_b_pub, spk_b_pub, their_opk_pub=opk_b_pub)
    sk_b = x3dh_responder(
        ik_b_priv, spk_b_priv, ik_a_pub, ek_a, my_opk_priv=opk_b_priv)
    assert sk_a == sk_b

    # Including a one-time prekey yields a DIFFERENT secret than SPK-only, and a
    # responder without the OPK (already consumed) cannot reproduce it.
    sk_no_opk, _ = x3dh_initiator(ik_a_priv, ik_b_pub, spk_b_pub)
    assert sk_a != sk_no_opk
    sk_b_missing = x3dh_responder(ik_b_priv, spk_b_priv, ik_a_pub, ek_a)
    assert sk_b_missing != sk_a


async def test_x3dh_consumes_one_time_prekey_end_to_end(identity_a, identity_b):
    """When the peer published OPKs, the sender uses one and the recipient
    deletes it after a validated delivery (one-time forward secrecy)."""
    from malphas.node import MalphasNode
    from malphas.obfuscation import pad_payload
    from malphas.sealed_sender import seal as seal_from

    node_a = MalphasNode(identity_a, "127.0.0.1", 17796, cover_traffic=False)
    node_b = MalphasNode(identity_b, "127.0.0.1", 17797, cover_traffic=False)

    node_a.discovery.add_peer(
        identity_b.peer_id, "127.0.0.1", 17797,
        identity_b.x25519_pub_bytes, identity_b.ed25519_pub_bytes,
        spk_pub=node_b.signed_prekey_pub,
        opks=list(node_b.one_time_prekeys_pub))
    node_b.discovery.add_peer(
        identity_a.peer_id, "127.0.0.1", 17796,
        identity_a.x25519_pub_bytes, identity_a.ed25519_pub_bytes)

    got = []
    node_b.on_message(lambda frm, content: got.append(content))
    n_before = len(node_b._opk_privs)

    dest_peer = node_a.discovery.get_peer(identity_b.peer_id)
    from_eph, from_sealed = seal_from(identity_a.peer_id, identity_b.x25519_pub_bytes)
    payload = json.dumps({
        "kind": "msg", "from_eph": from_eph, "from_sealed": from_sealed,
        "content": "opk secret", "msg_id": "o1",
        "nonce": "22" * 16, "ts": int(time.time()),
    }).encode()

    wrapped = node_a._wrap_for_dest(payload, identity_b.peer_id, dest_peer)
    assert wrapped[0:1] == b"X"
    # A one-time prekey was included (OPK_B field is non-zero).
    assert wrapped[97:129] != b"\x00" * 32

    await node_b._deliver(pad_payload(wrapped))
    await asyncio.sleep(0.05)
    assert "opk secret" in got
    # Exactly one OPK consumed (deleted) by the recipient.
    assert len(node_b._opk_privs) == n_before - 1
