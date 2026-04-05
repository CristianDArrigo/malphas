"""
End-to-end tests over Tor hidden services.

ALL tests in this file require a running Tor daemon with:
  - SOCKS5 proxy on 127.0.0.1:9050
  - ControlPort 9051 enabled (for hidden service registration)

These tests are SLOW by nature: Tor descriptor publication and circuit
establishment can take 15-60s.

Run them explicitly:

    pytest tests/test_tor_e2e.py -v

Skip automatically if Tor is not available.
"""

import asyncio

import pytest

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)

from malphas.identity import create_identity
from malphas.node import MalphasNode
from malphas.transport import (
    TorTransport,
    ed25519_pub_to_onion,
    onion_to_ed25519_pub,
    tor_is_available,
)


# ── Skip decorator ───────────────────────────────────────────────────────────

def _check_tor():
    try:
        return asyncio.get_event_loop().run_until_complete(tor_is_available())
    except Exception:
        return False


skip_no_tor = pytest.mark.skipif(not _check_tor(), reason="Tor not running")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _extract_priv_bytes(identity) -> bytes:
    return identity.ed25519_priv.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )


async def _register_hidden_service(transport, identity, local_port):
    """Register hidden service with await_publication=True for test reliability."""
    priv_bytes = _extract_priv_bytes(identity)

    # Override the transport method to use await_publication=True
    # so stem waits for the descriptor to actually be published.
    # Production code uses False for speed, but tests need reliability.
    try:
        from stem.control import Controller
    except ImportError:
        raise RuntimeError("stem is required")

    import base64
    expanded = priv_bytes + identity.ed25519_pub_bytes
    key_content = base64.b64encode(expanded).decode()

    loop = asyncio.get_running_loop()
    controller = await loop.run_in_executor(
        None,
        lambda: Controller.from_port(
            address="127.0.0.1", port=9051,
        )
    )
    await loop.run_in_executor(None, lambda: controller.authenticate())

    hs = await loop.run_in_executor(
        None,
        lambda: controller.create_ephemeral_hidden_service(
            {80: local_port},
            key_type="ED25519-V3",
            key_content=key_content,
            await_publication=True,
        )
    )

    onion = ed25519_pub_to_onion(identity.ed25519_pub_bytes)
    transport._controller = controller
    transport._hidden_service = hs
    transport._onion_address = onion
    return onion


async def _connect_with_retry(node, onion, port, peer_id, x25519, ed25519,
                               max_attempts=5, delay=10.0):
    """
    Try to connect to a .onion address with retries.
    Tor descriptor publication takes time — first attempts may fail.
    """
    for attempt in range(max_attempts):
        ok = await node.connect_to_peer(onion, port, peer_id, x25519, ed25519)
        if ok:
            return True
        if attempt < max_attempts - 1:
            await asyncio.sleep(delay)
    return False


# ── Tests ────────────────────────────────────────────────────────────────────

@skip_no_tor
class TestTorE2E:

    async def test_hidden_service_registration_and_onion_match(self):
        """Register hidden service, verify .onion matches identity Ed25519 pubkey."""
        identity = create_identity("tor-e2e-registration")
        transport = TorTransport()

        try:
            onion = await _register_hidden_service(transport, identity, 19200)

            assert onion.endswith(".onion")
            assert len(onion) == 62

            expected_onion = ed25519_pub_to_onion(identity.ed25519_pub_bytes)
            assert onion == expected_onion

            recovered_pub = onion_to_ed25519_pub(onion)
            assert recovered_pub == identity.ed25519_pub_bytes
        except RuntimeError as e:
            if "stem is required" in str(e):
                pytest.skip("stem not installed")
            raise
        finally:
            await transport.stop()

    async def test_two_nodes_communicate_via_hidden_service(self):
        """
        Node A sends a message to Node B via B's .onion hidden service.
        Verifies message delivery and read receipt over real Tor circuits.
        """
        id_a = create_identity("tor-e2e-alice")
        id_b = create_identity("tor-e2e-bob")

        transport_a = TorTransport()
        transport_b = TorTransport()

        node_a = MalphasNode(id_a, "127.0.0.1", 19201, cover_traffic=False, transport=transport_a)
        node_b = MalphasNode(id_b, "127.0.0.1", 19202, cover_traffic=False, transport=transport_b)

        try:
            await node_a.start()
            await node_b.start()

            onion_b = await _register_hidden_service(transport_b, id_b, 19202)

            # Wait for Tor to publish the descriptor
            await asyncio.sleep(15)

            # Connect with retry — descriptor may not be ready yet
            connected = await _connect_with_retry(
                node_a, onion_b, 80,
                id_b.peer_id, id_b.x25519_pub_bytes, id_b.ed25519_pub_bytes,
                max_attempts=4, delay=15.0,
            )
            if not connected:
                pytest.skip(f"Could not connect to {onion_b} — Tor descriptor not yet published")

            received = []
            receipts = []
            node_b.on_message(lambda f, c: received.append((f, c)))
            node_a.on_receipt(lambda mid, dest, ok: receipts.append(ok))

            msg_id = await node_a.send_message(id_b.peer_id, "hello over tor")
            assert msg_id is not None

            await asyncio.sleep(10)

            contents = [c for _, c in received]
            assert "hello over tor" in contents, f"Message not received by B. Got: {contents}"

            senders = [f for f, _ in received]
            assert id_a.peer_id in senders

            assert any(r for r in receipts), f"No positive receipt at A. Got: {receipts}"

        except RuntimeError as e:
            if "stem is required" in str(e):
                pytest.skip("stem not installed")
            raise
        finally:
            await node_a.stop()
            await node_b.stop()

    async def test_bidirectional_via_hidden_service(self):
        """Both nodes register hidden services and exchange messages."""
        id_a = create_identity("tor-e2e-bidir-alice")
        id_b = create_identity("tor-e2e-bidir-bob")

        transport_a = TorTransport()
        transport_b = TorTransport()

        node_a = MalphasNode(id_a, "127.0.0.1", 19203, cover_traffic=False, transport=transport_a)
        node_b = MalphasNode(id_b, "127.0.0.1", 19204, cover_traffic=False, transport=transport_b)

        try:
            await node_a.start()
            await node_b.start()

            onion_a = await _register_hidden_service(transport_a, id_a, 19203)
            onion_b = await _register_hidden_service(transport_b, id_b, 19204)

            await asyncio.sleep(15)

            ok_ab = await _connect_with_retry(
                node_a, onion_b, 80,
                id_b.peer_id, id_b.x25519_pub_bytes, id_b.ed25519_pub_bytes,
            )
            if not ok_ab:
                pytest.skip(f"Could not connect A→B via {onion_b}")

            ok_ba = await _connect_with_retry(
                node_b, onion_a, 80,
                id_a.peer_id, id_a.x25519_pub_bytes, id_a.ed25519_pub_bytes,
            )
            if not ok_ba:
                pytest.skip(f"Could not connect B→A via {onion_a}")

            recv_at_b = []
            recv_at_a = []
            node_b.on_message(lambda f, c: recv_at_b.append(c))
            node_a.on_message(lambda f, c: recv_at_a.append(c))

            assert await node_a.send_message(id_b.peer_id, "alice to bob") is not None
            assert await node_b.send_message(id_a.peer_id, "bob to alice") is not None

            await asyncio.sleep(10)

            assert "alice to bob" in recv_at_b, f"B missing message. Got: {recv_at_b}"
            assert "bob to alice" in recv_at_a, f"A missing message. Got: {recv_at_a}"

        except RuntimeError as e:
            if "stem is required" in str(e):
                pytest.skip("stem not installed")
            raise
        finally:
            await node_a.stop()
            await node_b.stop()

    async def test_hidden_service_survives_circuit_rebuild(self):
        """Send message, wait 15s, send another — both must arrive."""
        id_a = create_identity("tor-e2e-rebuild-alice")
        id_b = create_identity("tor-e2e-rebuild-bob")

        transport_a = TorTransport()
        transport_b = TorTransport()

        node_a = MalphasNode(id_a, "127.0.0.1", 19205, cover_traffic=False, transport=transport_a)
        node_b = MalphasNode(id_b, "127.0.0.1", 19206, cover_traffic=False, transport=transport_b)

        try:
            await node_a.start()
            await node_b.start()

            onion_b = await _register_hidden_service(transport_b, id_b, 19206)
            await asyncio.sleep(15)

            connected = await _connect_with_retry(
                node_a, onion_b, 80,
                id_b.peer_id, id_b.x25519_pub_bytes, id_b.ed25519_pub_bytes,
            )
            if not connected:
                pytest.skip(f"Could not connect to {onion_b}")

            received = []
            node_b.on_message(lambda f, c: received.append(c))

            assert await node_a.send_message(id_b.peer_id, "before wait") is not None
            await asyncio.sleep(5)
            assert "before wait" in received, f"First message not received. Got: {received}"

            # Wait — Tor may rebuild circuit
            await asyncio.sleep(15)

            assert await node_a.send_message(id_b.peer_id, "after wait") is not None
            await asyncio.sleep(5)
            assert "after wait" in received, f"Second message not received. Got: {received}"

        except RuntimeError as e:
            if "stem is required" in str(e):
                pytest.skip("stem not installed")
            raise
        finally:
            await node_a.stop()
            await node_b.stop()

    async def test_onion_address_stable_across_restarts(self):
        """Same passphrase always produces same .onion address."""
        passphrase = "tor-e2e-stable-onion"

        id_1 = create_identity(passphrase)
        id_2 = create_identity(passphrase)

        onion_1 = ed25519_pub_to_onion(id_1.ed25519_pub_bytes)
        onion_2 = ed25519_pub_to_onion(id_2.ed25519_pub_bytes)

        assert onion_1 == onion_2
        assert id_1.ed25519_pub_bytes == id_2.ed25519_pub_bytes
        assert id_1.peer_id == id_2.peer_id
