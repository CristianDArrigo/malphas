"""
Node: main async event loop.
Manages TCP server, peer connections, onion routing, message delivery.

Integrates:
- Read receipts (Ed25519 challenge-response)
- Message padding (PAYLOAD_BLOCK alignment)
- Cover traffic (randomized dummy packets)

No logging to disk. No persistence.
"""

import asyncio
import json
import secrets
import time
from typing import Callable, Dict, Optional, Set

from .crypto import (
    decrypt,
    derive_session_key,
    ecdh_shared_secret,
    encrypt,
    generate_ephemeral_keypair,
)
from .discovery import PeerDiscovery, PeerInfo
from .identity import Identity
from .memory import MessageStore
from .obfuscation import (
    CoverTrafficEngine,
    is_cover,
    make_cover_payload,
    pad_payload,
    unpad_payload,
)
from .onion import peel_layer, wrap_onion
from .transport import BaseTransport, DirectTransport
from .receipts import ReceiptTracker, sign_receipt

# Wire message types
MSG_HANDSHAKE     = 0x01
MSG_HANDSHAKE_ACK = 0x02
MSG_ONION         = 0x03
MSG_PING          = 0x05
MSG_PONG          = 0x06
MSG_PEER_ANNOUNCE = 0x07

HEADER_LEN = 5   # type(1) + length(4)

# Payload kinds (inside decrypted onion)
KIND_MESSAGE = "msg"
KIND_RECEIPT = "receipt"
KIND_COVER   = "cover"


def _pack_msg(msg_type: int, payload: bytes) -> bytes:
    import struct
    return struct.pack(">BI", msg_type, len(payload)) + payload


def _unpack_header(data: bytes):
    import struct
    if len(data) < HEADER_LEN:
        return None, None
    msg_type, length = struct.unpack(">BI", data[:HEADER_LEN])
    return msg_type, length


class PeerConnection:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer_info: Optional[PeerInfo] = None,
    ):
        self.reader = reader
        self.writer = writer
        self.peer_info = peer_info
        self.session_key: Optional[bytes] = None
        self.authenticated = False

    async def send(self, msg_type: int, payload: bytes) -> None:
        data = _pack_msg(msg_type, payload)
        self.writer.write(data)
        await self.writer.drain()

    async def send_encrypted(self, msg_type: int, payload: bytes) -> None:
        if not self.session_key:
            raise RuntimeError("No session key")
        ct = encrypt(self.session_key, payload)
        await self.send(msg_type, ct)

    async def recv_raw(self) -> tuple:
        header = await self.reader.readexactly(HEADER_LEN)
        msg_type, length = _unpack_header(header)
        payload = await self.reader.readexactly(length)
        return msg_type, payload

    def close(self) -> None:
        try:
            self.writer.close()
        except Exception:
            pass


class MalphasNode:
    def __init__(
        self,
        identity: Identity,
        host: str = "0.0.0.0",
        port: int = 7777,
        message_ttl: int = 3600,
        cover_traffic: bool = True,
        transport: Optional[BaseTransport] = None,
    ):
        self.identity = identity
        self.host = host
        self.port = port
        self.transport: BaseTransport = transport or DirectTransport()
        self.discovery = PeerDiscovery(identity.peer_id)
        self.store = MessageStore(ttl_seconds=message_ttl)
        self.receipts = ReceiptTracker()
        self._connections: Dict[str, PeerConnection] = {}
        self._server: Optional[asyncio.AbstractServer] = None
        self._callbacks: Set[Callable] = set()
        self._receipt_callbacks: Set[Callable] = set()
        self._running = False

        # Cover traffic engine
        self._cover = CoverTrafficEngine(
            get_peers_fn=lambda: list(self._connections.keys()),
            send_cover_fn=self._send_cover_packet,
        ) if cover_traffic else None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        self._running = True
        self._server = await self.transport.start_server(
            self.host, self.port, self._handle_incoming
        )
        await self.receipts.start()
        if self._cover:
            await self._cover.start()
        asyncio.create_task(self._purge_loop())
        asyncio.create_task(self._ping_loop())

        # Receipt callbacks
        self.receipts.on_receipt(self._on_receipt_resolved)
        self.receipts.on_timeout(self._on_receipt_timeout)

    async def stop(self) -> None:
        self._running = False
        if self._cover:
            await self._cover.stop()
        await self.receipts.stop()
        await self.transport.stop()
        for conn in list(self._connections.values()):
            conn.close()
        self.store.wipe()
        self.discovery.wipe()


    @property
    def public_address(self) -> Optional[str]:
        return self.transport.public_address or self.host

    # ── Callbacks ─────────────────────────────────────────────────────────────

    def on_message(self, callback: Callable) -> None:
        self._callbacks.add(callback)

    def on_receipt(self, callback: Callable) -> None:
        """callback(msg_id, dest_peer_id, received: bool)"""
        self._receipt_callbacks.add(callback)

    def _notify_message(self, from_id: str, content: str) -> None:
        for cb in self._callbacks:
            try:
                asyncio.create_task(cb(from_id, content))
            except Exception:
                pass

    def _notify_receipt(self, msg_id: str, dest_id: str, received: bool) -> None:
        for cb in self._receipt_callbacks:
            try:
                asyncio.create_task(cb(msg_id, dest_id, received))
            except Exception:
                pass

    async def _on_receipt_resolved(self, msg_id: str, dest_id: str, received: bool) -> None:
        self._notify_receipt(msg_id, dest_id, received)

    async def _on_receipt_timeout(self, msg_id: str, dest_id: str) -> None:
        self._notify_receipt(msg_id, dest_id, False)

    # ── Outbound ──────────────────────────────────────────────────────────────

    async def connect_to_peer(
        self,
        host: str,
        port: int,
        peer_id: str,
        x25519_pub: bytes,
        ed25519_pub: bytes,
    ) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                self.transport.connect(host, port), timeout=30.0
            )
            conn = PeerConnection(reader, writer)
            ok = await self._perform_handshake(conn, outbound=True)
            if ok and conn.peer_info:
                self._connections[conn.peer_info.peer_id] = conn
                self.discovery.add_peer(peer_id, host, port, x25519_pub, ed25519_pub)
                asyncio.create_task(self._read_loop(conn))
            else:
                conn.close()
            return ok
        except Exception:
            return False

    async def send_message(self, dest_peer_id: str, content: str) -> Optional[str]:
        """
        Send a message. Returns msg_id if queued, None on failure.
        """
        try:
            circuit = self.discovery.select_relay_circuit(dest_peer_id, hops=3)
        except ValueError:
            return None

        msg_id = secrets.token_hex(16)
        nonce = secrets.token_bytes(16)

        payload_dict = {
            "kind": KIND_MESSAGE,
            "from": self.identity.peer_id,
            "content": content,
            "msg_id": msg_id,
            "nonce": nonce.hex(),
            "ts": time.time(),
        }
        payload_bytes = json.dumps(payload_dict).encode()

        # Sign
        sig = self.identity.sign(payload_bytes)
        signed = sig + payload_bytes

        # Pad to block boundary
        padded = pad_payload(signed)

        # Wrap in onion
        packet = wrap_onion(padded, circuit)

        first_hop_id = circuit[0][1]
        conn = self._connections.get(first_hop_id)
        if conn and conn.authenticated:
            await conn.send_encrypted(MSG_ONION, packet[24:])  # strip first_hop_id(20)+len(4)
            # Track read receipt
            self.receipts.track(msg_id, nonce, dest_peer_id, content)
            # Store locally as sent
            self.store.store(self.identity.peer_id, dest_peer_id, content, msg_id)
            return msg_id
        return None

    async def _send_cover_packet(self, peer_id: str) -> None:
        """Send a cover traffic packet to a peer. Routed as onion if possible."""
        conn = self._connections.get(peer_id)
        if not conn or not conn.authenticated:
            return

        cover_payload = make_cover_payload()

        # Try to build a 1-hop onion (direct to peer)
        peer = self.discovery.get_peer(peer_id)
        if not peer:
            return

        try:
            circuit = [(peer.x25519_pub, peer_id)]
            packet = wrap_onion(cover_payload, circuit)
            await conn.send_encrypted(MSG_ONION, packet[24:])  # strip first_hop_id(20)+len(4)
        except Exception:
            pass

    async def _send_receipt(self, from_id: str, msg_id: str, nonce: bytes) -> None:
        """Send a read receipt back to the sender."""
        sig = sign_receipt(msg_id, nonce, self.identity.ed25519_priv)

        payload_dict = {
            "kind": KIND_RECEIPT,
            "from": self.identity.peer_id,
            "msg_id": msg_id,
            "sig": sig.hex(),
        }
        payload_bytes = json.dumps(payload_dict).encode()

        # Sign the receipt payload — _deliver expects sig(64) + json for all non-cover packets
        outer_sig = self.identity.sign(payload_bytes)
        signed = outer_sig + payload_bytes
        padded = pad_payload(signed)

        # Route back to sender if we have them in routing table
        try:
            circuit = self.discovery.select_relay_circuit(from_id, hops=3)
        except ValueError:
            return

        packet = wrap_onion(padded, circuit)
        first_hop_id = circuit[0][1]
        conn = self._connections.get(first_hop_id)
        if conn and conn.authenticated:
            await conn.send_encrypted(MSG_ONION, packet[24:])  # strip first_hop_id(20)+len(4)

    # ── Inbound ───────────────────────────────────────────────────────────────

    async def _handle_incoming(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        conn = PeerConnection(reader, writer)
        ok = await self._perform_handshake(conn, outbound=False)
        if ok and conn.peer_info:
            self._connections[conn.peer_info.peer_id] = conn
            await self._read_loop(conn)
        else:
            conn.close()

    async def _read_loop(self, conn: PeerConnection) -> None:
        try:
            while self._running:
                msg_type, payload = await conn.recv_raw()
                await self._dispatch(conn, msg_type, payload)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            if conn.peer_info:
                self._connections.pop(conn.peer_info.peer_id, None)
            conn.close()

    async def _dispatch(
        self, conn: PeerConnection, msg_type: int, payload: bytes
    ) -> None:
        if msg_type == MSG_PING:
            await conn.send(MSG_PONG, b"")
            return

        if msg_type == MSG_ONION:
            if conn.session_key:
                try:
                    payload = decrypt(conn.session_key, payload)
                except ValueError:
                    return
            await self._handle_onion(payload)
            return

        if msg_type == MSG_PEER_ANNOUNCE:
            await self._handle_peer_announce(payload)

    async def _handle_onion(self, data: bytes) -> None:
        """Peel one onion layer. Forward or deliver."""
        try:
            next_hop, inner = peel_layer(self.identity.x25519_priv, data)
        except ValueError:
            return

        if next_hop is None:
            # Final destination
            await self._deliver(inner)
        else:
            conn = self._connections.get(next_hop)
            if conn and conn.authenticated:
                await conn.send_encrypted(MSG_ONION, inner)

    async def _deliver(self, padded_payload: bytes) -> None:
        """Unpad, verify, and deliver a payload meant for us."""
        try:
            signed = unpad_payload(padded_payload)
        except ValueError:
            return

        # Check for cover traffic first (no signature prefix)
        if is_cover(signed):
            return  # silently drop — this is correct behavior

        # Real payload: 64-byte Ed25519 sig + JSON
        if len(signed) < 64:
            return

        sig = signed[:64]
        payload_bytes = signed[64:]

        try:
            data = json.loads(payload_bytes.decode())
        except Exception:
            return

        kind = data.get("kind")
        from_id = data.get("from", "")

        if not kind or not from_id:
            return

        # Verify signature if we know the sender
        peer = self.discovery.get_peer(from_id)
        if peer:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            try:
                pub = Ed25519PublicKey.from_public_bytes(peer.ed25519_pub)
                pub.verify(sig, payload_bytes)
            except Exception:
                return  # invalid signature — drop

        if kind == KIND_MESSAGE:
            await self._deliver_message(data, from_id)

        elif kind == KIND_RECEIPT:
            await self._deliver_receipt(data, from_id, peer)

        elif kind == KIND_COVER:
            pass  # JSON-level cover, drop silently

    async def _deliver_message(self, data: dict, from_id: str) -> None:
        content = data.get("content", "")
        msg_id = data.get("msg_id", "")
        nonce_hex = data.get("nonce", "")

        if not content or not msg_id or not nonce_hex:
            return

        try:
            nonce = bytes.fromhex(nonce_hex)
        except ValueError:
            return

        self.store.store(from_id, self.identity.peer_id, content, msg_id)
        self._notify_message(from_id, content)

        # Send read receipt asynchronously
        asyncio.create_task(self._send_receipt(from_id, msg_id, nonce))

    async def _deliver_receipt(self, data: dict, from_id: str, peer) -> None:
        msg_id = data.get("msg_id", "")
        sig_hex = data.get("sig", "")

        if not msg_id or not sig_hex or not peer:
            return

        try:
            sig = bytes.fromhex(sig_hex)
        except ValueError:
            return

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub = Ed25519PublicKey.from_public_bytes(peer.ed25519_pub)
        self.receipts.resolve(msg_id, sig, pub)

    async def _handle_peer_announce(self, payload: bytes) -> None:
        try:
            data = json.loads(payload.decode())
            self.discovery.add_peer(
                data["peer_id"], data["host"], data["port"],
                bytes.fromhex(data["x25519_pub"]),
                bytes.fromhex(data["ed25519_pub"]),
            )
        except Exception:
            pass

    # ── Handshake ─────────────────────────────────────────────────────────────

    async def _perform_handshake(
        self, conn: PeerConnection, outbound: bool
    ) -> bool:
        try:
            eph_priv, eph_pub = generate_ephemeral_keypair()
            hello = json.dumps({
                "eph_pub": eph_pub.hex(),
                "peer_id": self.identity.peer_id,
                "x25519_pub": self.identity.x25519_pub_bytes.hex(),
                "ed25519_pub": self.identity.ed25519_pub_bytes.hex(),
                "port": self.port,
            }).encode()

            await conn.send(
                MSG_HANDSHAKE if outbound else MSG_HANDSHAKE_ACK, hello
            )

            expected = MSG_HANDSHAKE_ACK if outbound else MSG_HANDSHAKE
            msg_type, their_hello = await asyncio.wait_for(
                conn.recv_raw(), timeout=10.0
            )
            if msg_type != expected:
                return False

            their_data = json.loads(their_hello.decode())
            their_eph = bytes.fromhex(their_data["eph_pub"])
            their_x25519 = bytes.fromhex(their_data["x25519_pub"])
            their_ed25519 = bytes.fromhex(their_data["ed25519_pub"])
            their_peer_id = their_data["peer_id"]
            their_port = their_data.get("port", self.port)

            shared = ecdh_shared_secret(eph_priv, their_eph)
            role = "initiator" if outbound else "responder"
            session_key = derive_session_key(shared, eph_pub, their_eph, role)

            conn.session_key = session_key
            conn.authenticated = True

            host = conn.writer.get_extra_info("peername")[0]
            peer = self.discovery.add_peer(
                their_peer_id, host, their_port, their_x25519, their_ed25519
            )
            conn.peer_info = peer
            return True
        except Exception:
            return False

    # ── Panic wipe ───────────────────────────────────────────────────────────────

    def panic(self) -> None:
        """
        Emergency in-memory wipe.
        Clears all sensitive state as fast as possible.
        Does NOT stop the event loop — call stop() separately.
        Designed to be called before physical device compromise.
        """
        # Wipe message store
        self.store.wipe()

        # Wipe routing table and peer info
        self.discovery.wipe()

        # Wipe pending receipts
        self.receipts.wipe()

        # Close all active connections immediately
        for conn in list(self._connections.values()):
            try:
                conn.close()
            except Exception:
                pass
        self._connections.clear()

        # Clear callbacks (prevent any further processing)
        self._callbacks.clear()
        self._receipt_callbacks.clear()

        # Force garbage collection to reclaim memory
        import gc
        gc.collect()

    # ── Background tasks ──────────────────────────────────────────────────────────

    async def _purge_loop(self) -> None:
        while self._running:
            await asyncio.sleep(60)
            self.store.purge_expired()
            self.discovery.table.purge_stale()

    async def _ping_loop(self) -> None:
        while self._running:
            await asyncio.sleep(30)
            dead = []
            for peer_id, conn in list(self._connections.items()):
                try:
                    await conn.send(MSG_PING, b"")
                except Exception:
                    dead.append(peer_id)
            for peer_id in dead:
                self._connections.pop(peer_id, None)
