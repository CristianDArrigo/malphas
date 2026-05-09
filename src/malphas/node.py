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
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
    )

from .crypto import (
    decrypt,
    derive_hmac_key,
    derive_session_key,
    ecdh_shared_secret,
    encrypt,
    generate_ephemeral_keypair,
    hmac_sign,
    hmac_verify,
)
from .discovery import PeerDiscovery, PeerInfo
from .files import FileOffer, FileTransferManager, OutgoingFile
from .groups import MAX_MEMBERS, Group, GroupRegistry
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
from .pinstore import PinStore
from .ratchet import MessageHeader, RatchetState
from .receipts import ReceiptTracker, sign_receipt
from .replay import ReplayCache
from .sealed_sender import seal as seal_from
from .sealed_sender import unseal as unseal_from
from .transport import BaseTransport, DirectTransport

# Wire-protocol version. Bumped when the byte-level layout of
# anything in PROTOCOL.md sections 4-9 changes. Frozen at 1 from
# release `1.0.0-rc1` onward; further changes go through the
# additive-only rules in PROTOCOL.md §10.
WIRE_VERSION = 1

# Wire message types
MSG_HANDSHAKE     = 0x01
MSG_HANDSHAKE_ACK = 0x02
MSG_ONION         = 0x03
MSG_PING          = 0x05
MSG_PONG          = 0x06
MSG_PEER_ANNOUNCE = 0x07

HEADER_LEN = 5   # type(1) + length(4)

# Authentication-type prefix on the inner authenticated payload
# (post-onion-peel, post-padding-strip). Exactly one byte; the receiver
# dispatches on this byte to pick the right authentication path.
# Wire format introduced in v0.4.0 — older clients (<= 0.3.x) won't be
# able to decode messages from new clients and vice-versa.
AUTH_RATCHET = b"R"   # b"R" || header(40) || ratchet ciphertext
AUTH_HMAC    = b"H"   # b"H" || tag(32)    || JSON payload bytes
AUTH_ED25519 = b"E"   # b"E" || sig(64)    || JSON payload bytes

HMAC_TAG_LEN     = 32
ED25519_SIG_LEN  = 64
RATCHET_HEADER_LEN = 40

# Payload kinds (inside decrypted onion)
KIND_MESSAGE     = "msg"
KIND_RECEIPT     = "receipt"
KIND_COVER       = "cover"
KIND_FILE_OFFER  = "file_offer"
KIND_FILE_CHUNK  = "file_chunk"
KIND_FILE_ACK    = "file_ack"
KIND_FILE_RESUME = "file_resume"
KIND_GROUP_INVITE = "group_invite"
KIND_GROUP_MSG    = "group_msg"
KIND_GROUP_MEMBER_CHANGE = "group_member_change"   # added in 1.0.0-rc3


def _pack_msg(msg_type: int, payload: bytes) -> bytes:
    import struct
    return struct.pack(">BI", msg_type, len(payload)) + payload


def _unpack_header(data: bytes):
    import struct
    if len(data) < HEADER_LEN:
        return None, None
    msg_type, length = struct.unpack(">BI", data[:HEADER_LEN])
    return msg_type, length


def _resolve_sealed_from(
        data: dict, my_x25519_priv: "X25519PrivateKey") -> str:
    """
    Recover the sender peer_id from a sealed envelope embedded in
    `data` (`from_eph` + `from_sealed`). Returns the empty string on
    any failure — the caller treats that as a "drop silently" signal.
    Also injects `data["from"] = <real_from>` on success so the rest
    of the dispatch pipeline can read it as before.
    """
    eph_hex = data.get("from_eph")
    sealed_b64 = data.get("from_sealed")
    if not eph_hex or not sealed_b64 or not isinstance(eph_hex, str) \
            or not isinstance(sealed_b64, str):
        return ""
    try:
        from_id = unseal_from(eph_hex, sealed_b64, my_x25519_priv)
    except ValueError:
        return ""
    data["from"] = from_id
    return from_id


def _wrap_authenticated(
    payload_bytes: bytes,
    dest_conn: "PeerConnection | None",
    identity: Identity,
) -> bytes:
    """
    Authenticate `payload_bytes` with the strongest method available
    on the connection and prepend the auth-type prefix.

    Selection order: ratchet → HMAC → Ed25519 (last-resort, fallback
    when no symmetric session has been negotiated, e.g. immediately
    after a fresh handshake handed off into a paired-but-pre-DH state).

    Returns: AUTH_TAG (1B) || material || payload (or for ratchet,
    AUTH_RATCHET || header(40) || ciphertext — the JSON is encrypted).
    """
    if dest_conn and dest_conn.ratchet and dest_conn.ratchet._send_chain_key:
        header, ciphertext = dest_conn.ratchet.encrypt(payload_bytes)
        return AUTH_RATCHET + header.serialize() + ciphertext
    if dest_conn and dest_conn.hmac_key:
        tag = hmac_sign(dest_conn.hmac_key, payload_bytes)
        return AUTH_HMAC + tag + payload_bytes
    sig = identity.sign(payload_bytes)
    return AUTH_ED25519 + sig + payload_bytes


def _snapshot_ratchet(r: "RatchetState") -> dict:
    """Save mutable ratchet state so it can be restored after a failed trial decrypt."""
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    priv_bytes = None
    if r._dh_priv is not None:
        priv_bytes = r._dh_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return {
        "priv": priv_bytes,
        "pub": r._dh_pub,
        "remote": r._remote_dh_pub,
        "root": r._root_key,
        "send_ck": r._send_chain_key,
        "recv_ck": r._recv_chain_key,
        "send_n": r._send_msg_num,
        "recv_n": r._recv_msg_num,
        "prev": r._prev_send_count,
        "skipped": dict(r._skipped),
    }


def _restore_ratchet(r: "RatchetState", snap: dict) -> None:
    """Restore ratchet state from a snapshot after a failed trial decrypt."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    if snap["priv"] is not None:
        r._dh_priv = X25519PrivateKey.from_private_bytes(snap["priv"])
    else:
        r._dh_priv = None
    r._dh_pub = snap["pub"]
    r._remote_dh_pub = snap["remote"]
    r._root_key = snap["root"]
    r._send_chain_key = snap["send_ck"]
    r._recv_chain_key = snap["recv_ck"]
    r._send_msg_num = snap["send_n"]
    r._recv_msg_num = snap["recv_n"]
    r._prev_send_count = snap["prev"]
    r._skipped = snap["skipped"]


class PeerConnection:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer_info: PeerInfo | None = None,
    ):
        self.reader = reader
        self.writer = writer
        self.peer_info = peer_info
        self.session_key: bytes | None = None
        self.hmac_key: bytes | None = None
        self.ratchet: RatchetState | None = None
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
        transport: BaseTransport | None = None,
        pin_store: PinStore | None = None,
    ):
        self.identity = identity
        self.host = host
        self.port = port
        self.transport: BaseTransport = transport or DirectTransport()
        self.discovery = PeerDiscovery(identity.peer_id)
        self.store = MessageStore(ttl_seconds=message_ttl)
        self.receipts = ReceiptTracker()
        self.pins = pin_store or PinStore()
        self._replay = ReplayCache(ttl=message_ttl)
        self._files = FileTransferManager()
        # Resume protocol (v0.8.0): when we send a file, we wait briefly
        # for the receiver to tell us which chunk indices it already has.
        # Keyed by file_id. The Event is set when a file_resume arrives.
        self._resume_signals: dict[str, set[int]] = {}
        self._resume_events: dict[str, asyncio.Event] = {}
        # Group chat (v0.9.0): in-memory registry of groups we're in.
        self._groups = GroupRegistry()
        self.auto_accept_files = False
        self._connections: dict[str, PeerConnection] = {}
        self._server: asyncio.AbstractServer | None = None
        self._callbacks: set[Callable] = set()
        self._receipt_callbacks: set[Callable] = set()
        self._pin_callbacks: set[Callable] = set()
        self._file_offer_callbacks: set[Callable] = set()
        self._file_complete_callbacks: set[Callable] = set()
        self._group_invite_callbacks: set[Callable] = set()
        self._group_message_callbacks: set[Callable] = set()
        self._group_member_change_callbacks: set[Callable] = set()
        self._running = False
        self._reconnect_book = None  # set by CLI to enable auto-reconnect
        self._reconnect_tasks: dict[str, asyncio.Task] = {}
        self._message_queue: dict[str, list] = {}  # peer_id -> [(content, msg_id)]
        self._queue_limit = 100  # max queued messages per peer

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
        self._bg_tasks = [
            asyncio.create_task(self._purge_loop()),
            asyncio.create_task(self._ping_loop()),
        ]

        # Receipt callbacks
        self.receipts.on_receipt(self._on_receipt_resolved)
        self.receipts.on_timeout(self._on_receipt_timeout)

    async def stop(self) -> None:
        self._running = False
        # Cancel background tasks immediately (don't wait for sleep to finish)
        for task in getattr(self, '_bg_tasks', []):
            task.cancel()
        for task in list(self._reconnect_tasks.values()):
            task.cancel()
        self._reconnect_tasks.clear()
        if self._cover:
            await self._cover.stop()
        await self.receipts.stop()
        await self.transport.stop()
        for conn in list(self._connections.values()):
            conn.close()
        self.store.wipe()
        self.discovery.wipe()


    @property
    def public_address(self) -> str | None:
        return self.transport.public_address or self.host

    # ── Callbacks ─────────────────────────────────────────────────────────────

    def on_message(self, callback: Callable) -> None:
        self._callbacks.add(callback)

    def on_receipt(self, callback: Callable) -> None:
        """callback(msg_id, dest_peer_id, received: bool)"""
        self._receipt_callbacks.add(callback)

    def on_pin_violation(self, callback: Callable) -> None:
        """callback(peer_id, expected_key_hex, received_key_hex)"""
        self._pin_callbacks.add(callback)

    def on_file_offer(self, callback: Callable) -> None:
        """callback(from_peer_id, offer_dict). User decides accept/reject."""
        self._file_offer_callbacks.add(callback)

    def on_file_complete(self, callback: Callable) -> None:
        """callback(file_id, payload_bytes) when a file is fully assembled."""
        self._file_complete_callbacks.add(callback)

    def on_group_invite(self, callback: Callable) -> None:
        """callback(from_peer_id, group_id, group_name, members) on group_invite."""
        self._group_invite_callbacks.add(callback)

    def on_group_message(self, callback: Callable) -> None:
        """callback(from_peer_id, group_id, group_name, content) on group_msg."""
        self._group_message_callbacks.add(callback)

    def on_group_member_change(self, callback: Callable) -> None:
        """callback(from_peer_id, group_id, action, target_peer_id, members)
        when membership changes. `action` is "add" or "remove";
        `target_peer_id` is the peer being added/removed; `members`
        is the new full list."""
        self._group_member_change_callbacks.add(callback)

    def _notify_group_invite(self, from_id: str, group_id: str,
                             group_name: str, members: list) -> None:
        for cb in self._group_invite_callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    asyncio.create_task(cb(from_id, group_id, group_name, members))
                else:
                    cb(from_id, group_id, group_name, members)
            except Exception:
                pass

    def _notify_group_message(self, from_id: str, group_id: str,
                              group_name: str, content: str) -> None:
        for cb in self._group_message_callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    asyncio.create_task(cb(from_id, group_id, group_name, content))
                else:
                    cb(from_id, group_id, group_name, content)
            except Exception:
                pass

    def _notify_group_member_change(self, from_id: str, group_id: str,
                                     action: str, target: str,
                                     members: list) -> None:
        for cb in self._group_member_change_callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    asyncio.create_task(cb(from_id, group_id, action,
                                             target, members))
                else:
                    cb(from_id, group_id, action, target, members)
            except Exception:
                pass

    def _notify_file_offer(self, from_id: str, offer_dict: dict) -> None:
        for cb in self._file_offer_callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    asyncio.create_task(cb(from_id, offer_dict))
                else:
                    cb(from_id, offer_dict)
            except Exception:
                pass

    def _notify_file_complete(self, file_id: str, data: bytes) -> None:
        for cb in self._file_complete_callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    asyncio.create_task(cb(file_id, data))
                else:
                    cb(file_id, data)
            except Exception:
                pass

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
                # Flush queued messages after reconnection
                if peer_id in self._message_queue:
                    asyncio.create_task(self._flush_queue(peer_id))
            else:
                conn.close()
            return ok
        except Exception:
            return False

    async def send_message(self, dest_peer_id: str, content: str) -> str | None:
        """
        Send a message. Returns msg_id if sent or queued.
        Returns None only if peer is completely unknown.
        """
        msg_id = secrets.token_hex(16)

        # Try to send immediately
        sent = await self._try_send(dest_peer_id, content, msg_id)
        if sent:
            return msg_id

        # If peer is known but offline, queue for later delivery
        if self.discovery.get_peer(dest_peer_id):
            self._enqueue(dest_peer_id, content, msg_id)
            self.store.store(self.identity.peer_id, dest_peer_id, content, msg_id)
            return msg_id

        return None

    async def _try_send(self, dest_peer_id: str, content: str, msg_id: str) -> bool:
        """Attempt to send a message immediately. Returns True if sent."""
        try:
            circuit = self.discovery.select_relay_circuit(dest_peer_id, hops=3)
        except ValueError:
            return False

        nonce = secrets.token_bytes(16)

        # Sealed sender: encrypt the `from` field with the recipient's
        # static X25519 pubkey so post-compromise observers can't read it.
        dest_peer = self.discovery.get_peer(dest_peer_id)
        if dest_peer is None:
            return False
        from_eph, from_sealed = seal_from(self.identity.peer_id, dest_peer.x25519_pub)

        payload_dict = {
            "kind": KIND_MESSAGE,
            "from_eph": from_eph,
            "from_sealed": from_sealed,
            "content": content,
            "msg_id": msg_id,
            "nonce": nonce.hex(),
            "ts": time.time(),
        }
        payload_bytes = json.dumps(payload_dict).encode()

        dest_conn = self._connections.get(dest_peer_id)
        authenticated = _wrap_authenticated(
            payload_bytes, dest_conn, self.identity
        )

        padded = pad_payload(authenticated)
        packet = wrap_onion(padded, circuit)

        first_hop_id = circuit[0][1]
        conn = self._connections.get(first_hop_id)
        if conn and conn.authenticated:
            await conn.send_encrypted(MSG_ONION, packet[24:])
            self.receipts.track(msg_id, nonce, dest_peer_id, content)
            self.store.store(self.identity.peer_id, dest_peer_id, content, msg_id)
            return True
        return False

    def _enqueue(self, peer_id: str, content: str, msg_id: str) -> None:
        """Queue a message for later delivery."""
        if peer_id not in self._message_queue:
            self._message_queue[peer_id] = []
        queue = self._message_queue[peer_id]
        if len(queue) < self._queue_limit:
            queue.append((content, msg_id))

    async def _flush_queue(self, peer_id: str) -> None:
        """Send all queued messages for a peer after reconnection."""
        queue = self._message_queue.pop(peer_id, [])
        for content, msg_id in queue:
            await self._try_send(peer_id, content, msg_id)
            await asyncio.sleep(0.05)  # avoid flooding

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

        # Sealed sender on the receipt too — the original sender (the
        # destination of this receipt) decrypts the sealed `from`.
        dest_peer = self.discovery.get_peer(from_id)
        if dest_peer is None:
            return
        from_eph, from_sealed = seal_from(self.identity.peer_id, dest_peer.x25519_pub)

        payload_dict = {
            "kind": KIND_RECEIPT,
            "from_eph": from_eph,
            "from_sealed": from_sealed,
            "msg_id": msg_id,
            "sig": sig.hex(),
        }
        payload_bytes = json.dumps(payload_dict).encode()

        # Authenticate the receipt payload.
        # Ratchet preferred (forward secrecy), then HMAC (deniable), then Ed25519.
        # The inner Ed25519 sig (in the JSON "sig" field) provides
        # non-repudiation for the receipt itself.
        sender_conn = self._connections.get(from_id)
        authenticated = _wrap_authenticated(
            payload_bytes, sender_conn, self.identity
        )
        padded = pad_payload(authenticated)

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
        except (asyncio.IncompleteReadError, ConnectionResetError, OSError, Exception):
            pass
        finally:
            peer_id = conn.peer_info.peer_id if conn.peer_info else None
            if peer_id:
                self._connections.pop(peer_id, None)
            conn.close()

            # Schedule reconnect if this peer is in the address book
            # (set by the CLI layer via set_reconnect_book)
            if peer_id and self._running and self._reconnect_book:
                contact = self._reconnect_book.get_by_peer_id(peer_id)
                if contact:
                    asyncio.create_task(self._reconnect(contact))

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

        # Check for cover traffic first (no signature/hmac prefix)
        if is_cover(signed):
            return  # silently drop — this is correct behavior

        # Dispatch on the auth-type prefix byte. Wire format is set in v0.4.0:
        #   b"R" || ratchet_header(40) || ratchet_ciphertext
        #   b"H" || hmac_tag(32)       || JSON payload
        #   b"E" || ed25519_sig(64)    || JSON payload
        # Anything else, or a payload too short to carry the minimum, is
        # dropped silently. This eliminates the trial-JSON-parse offset
        # heuristic the previous wire format relied on.
        if not signed:
            return
        prefix = signed[0:1]

        if prefix == AUTH_RATCHET:
            if len(signed) <= 1 + RATCHET_HEADER_LEN:
                return
            header_bytes = signed[1:1 + RATCHET_HEADER_LEN]
            ciphertext = signed[1 + RATCHET_HEADER_LEN:]
            header = MessageHeader.deserialize(header_bytes)

            # Trial-decrypt across each connection's ratchet. State is
            # snapshotted before each attempt so a wrong-connection try
            # cannot corrupt the receiver-state of the right one.
            for _peer_id, conn in list(self._connections.items()):
                if not conn.ratchet:
                    continue
                ratchet = conn.ratchet
                snap = _snapshot_ratchet(ratchet)
                try:
                    payload_bytes = ratchet.decrypt(header, ciphertext)
                except Exception:
                    _restore_ratchet(ratchet, snap)
                    continue

                try:
                    data = json.loads(payload_bytes.decode())
                except Exception:
                    _restore_ratchet(ratchet, snap)
                    continue

                from_id = _resolve_sealed_from(data, self.identity.x25519_priv)
                kind = data.get("kind")
                if not from_id or not kind:
                    _restore_ratchet(ratchet, snap)
                    continue

                peer = self.discovery.get_peer(from_id)
                if not peer:
                    _restore_ratchet(ratchet, snap)
                    continue

                await self._dispatch_kind(data, from_id, peer)
                return
            # No ratchet could decrypt — drop
            return

        if prefix == AUTH_HMAC:
            if len(signed) < 1 + HMAC_TAG_LEN + 1:
                return
            tag = signed[1:1 + HMAC_TAG_LEN]
            payload_bytes = signed[1 + HMAC_TAG_LEN:]
        elif prefix == AUTH_ED25519:
            if len(signed) < 1 + ED25519_SIG_LEN + 1:
                return
            tag = signed[1:1 + ED25519_SIG_LEN]
            payload_bytes = signed[1 + ED25519_SIG_LEN:]
        else:
            return  # unknown prefix — drop

        try:
            data = json.loads(payload_bytes.decode())
        except Exception:
            return

        kind = data.get("kind")
        from_id = _resolve_sealed_from(data, self.identity.x25519_priv)
        if not kind or not from_id:
            return

        peer = self.discovery.get_peer(from_id)
        if not peer:
            return  # unknown sender — drop silently

        # Verify the auth tag matches the declared method.
        if prefix == AUTH_HMAC:
            sender_conn = self._connections.get(from_id)
            if not sender_conn or not sender_conn.hmac_key:
                return
            if not hmac_verify(sender_conn.hmac_key, payload_bytes, tag):
                return
        else:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
            try:
                pub = Ed25519PublicKey.from_public_bytes(peer.ed25519_pub)
                pub.verify(tag, payload_bytes)
            except Exception:
                return

        await self._dispatch_kind(data, from_id, peer)

    async def _dispatch_kind(
        self, data: dict, from_id: str, peer: PeerInfo | None
    ) -> None:
        """Single dispatch site for all message kinds, with replay guard."""
        kind = data.get("kind")
        msg_id = data.get("msg_id", "")

        # Replay protection across every kind (msg, receipt, file_*).
        # Cover packets carry no msg_id and are dropped before reaching here.
        if msg_id and self._replay.seen(from_id, msg_id):
            return

        if kind == KIND_MESSAGE:
            await self._deliver_message(data, from_id)
        elif kind == KIND_RECEIPT:
            if peer is not None:
                await self._deliver_receipt(data, from_id, peer)
        elif kind == KIND_FILE_OFFER:
            await self._handle_file_offer(data, from_id)
        elif kind == KIND_FILE_CHUNK:
            await self._handle_file_chunk(data, from_id)
        elif kind == KIND_FILE_ACK:
            await self._handle_file_ack(data, from_id)
        elif kind == KIND_FILE_RESUME:
            await self._handle_file_resume(data, from_id)
        elif kind == KIND_GROUP_INVITE:
            await self._handle_group_invite(data, from_id)
        elif kind == KIND_GROUP_MSG:
            await self._handle_group_msg(data, from_id)
        elif kind == KIND_GROUP_MEMBER_CHANGE:
            await self._handle_group_member_change(data, from_id)
        elif kind == KIND_COVER:
            pass  # drop silently

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

        # NOTE: replay protection is centralized in `_dispatch_kind` so it
        # covers every payload kind (msg, receipt, file_*).

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

    # ── File transfer ─────────────────────────────────────────────────────────

    async def _handle_file_offer(self, data: dict, from_id: str) -> None:
        """Receive an offer. Auto-accept if `auto_accept_files`; otherwise
        notify the application via `on_file_offer` callback. The application
        can then call `accept_file_offer(file_id)` to register reception.

        v0.8.0 resume: if the offer's file_id is already in the incoming
        registry (we have a partial buffer), we send back a `file_resume`
        listing the chunk indices we already hold and SKIP re-registration.
        """
        try:
            offer = FileOffer.from_dict(data)
        except (KeyError, ValueError):
            return

        # Resume path: we already have a partial incoming for this file_id.
        existing = self._files.get_incoming(offer.file_id)
        if existing is not None and not existing.is_complete():
            received = existing.received_indices()
            await self._try_send_payload(
                from_id,
                KIND_FILE_RESUME,
                {"file_id": offer.file_id, "received_idx": received},
            )
            return

        # Cap enforcement on the receiver side too — drop oversize offers
        # without registering anything.
        try:
            self._files.register_incoming(offer)
        except ValueError:
            return

        offer_dict = offer.to_dict()
        if self.auto_accept_files:
            # Already registered — notify application that an offer is being
            # received automatically.
            self._notify_file_offer(from_id, offer_dict)
        else:
            # Default policy: do NOT register; require explicit accept.
            self._files.drop_incoming(offer.file_id)
            self._notify_file_offer(from_id, offer_dict)

    def accept_file_offer(self, offer_dict: dict) -> bool:
        """Application-level accept: register the incoming buffer."""
        try:
            offer = FileOffer.from_dict(offer_dict)
            self._files.register_incoming(offer)
            return True
        except (KeyError, ValueError):
            return False

    async def _handle_file_chunk(self, data: dict, from_id: str) -> None:
        import base64
        file_id = data.get("file_id")
        chunk_idx = data.get("chunk_idx")
        data_b64 = data.get("data_b64")
        if not file_id or chunk_idx is None or not isinstance(data_b64, str):
            return
        ic = self._files.get_incoming(file_id)
        if ic is None:
            return  # unknown / not accepted — drop silently
        try:
            payload_bytes = base64.b64decode(data_b64)
        except Exception:
            return
        complete = ic.add_chunk(int(chunk_idx), payload_bytes)
        if complete:
            try:
                assembled = ic.assemble()
            except ValueError:
                # Integrity failure — drop and notify nothing
                self._files.cancel(file_id)
                return
            self._notify_file_complete(file_id, assembled)
            # Keep the entry until application wipes via /savefile or panic.

    async def _handle_file_ack(self, data: dict, from_id: str) -> None:
        file_id = data.get("file_id")
        status = data.get("status")
        if not file_id or status not in ("accepted", "rejected", "completed", "checksum_mismatch"):
            return
        if status in ("rejected", "checksum_mismatch"):
            self._files.cancel(file_id)

    async def _handle_file_resume(self, data: dict, from_id: str) -> None:
        """Receiver tells us which chunks they already hold.

        We record the set in `_resume_signals[file_id]` and wake any
        `send_file()` coroutine waiting on `_resume_events[file_id]`
        so it can skip those indices.
        """
        file_id = data.get("file_id")
        received = data.get("received_idx")
        if not isinstance(file_id, str) or not isinstance(received, list):
            return
        try:
            idx_set = {int(i) for i in received}
        except (TypeError, ValueError):
            return
        # Only honor resume signals for files we are actively sending.
        if self._files.get_outgoing(file_id) is None:
            return
        self._resume_signals[file_id] = idx_set
        ev = self._resume_events.get(file_id)
        if ev is not None:
            ev.set()

    # ── Group chat (v0.9.0) ───────────────────────────────────────────────────

    async def _handle_group_invite(self, data: dict, from_id: str) -> None:
        """Receive a group invite. Register the group locally and notify
        the application. The user does not have an explicit accept step
        for groups — being added is symmetric to receiving a 1-to-1
        message from a known contact (and if the sender isn't known,
        the dispatch chain has already rejected upstream)."""
        group_id = data.get("group_id")
        group_name = data.get("group_name")
        members = data.get("members")
        if not isinstance(group_id, str) or not isinstance(group_name, str) \
                or not isinstance(members, list):
            return
        try:
            members_list = [str(m) for m in members]
        except Exception:
            return
        if len(members_list) > MAX_MEMBERS:
            return
        # Build and register the group locally.
        group = Group(
            group_id=group_id,
            name=group_name,
            creator=from_id,
            members=members_list,
        )
        self._groups.register(group)
        self._notify_group_invite(from_id, group_id, group.name, members_list)

    async def _handle_group_member_change(
            self, data: dict, from_id: str) -> None:
        """Receive a notification that a group's membership changed.

        Validates that `from_id` is the creator of the group OR an
        existing member (otherwise we'd accept arbitrary remote
        rewrites). Reconciles local membership with the new list.
        Surfaces an event to the application layer.

        See PROTOCOL.md §13 (planned 1.1.0). Wire-additive in the
        meantime: 1.0 receivers that don't implement this kind drop
        the payload silently per §10.2.
        """
        group_id = data.get("group_id")
        action = data.get("action")
        target = data.get("target")
        members = data.get("members")
        if not isinstance(group_id, str) or not isinstance(action, str) \
                or not isinstance(target, str) \
                or not isinstance(members, list):
            return
        if action not in ("add", "remove"):
            return
        try:
            members_list = [str(m) for m in members]
        except Exception:
            return
        if len(members_list) > MAX_MEMBERS:
            return

        group = self._groups.get_by_id(group_id)
        if group is None:
            # We were never invited; ignore (we'd see no messages
            # anyway, since the sender's not fanning to us either).
            return

        # Authorization: only accept membership rewrites from a
        # member of the group as we currently see it. Creator is
        # implicitly a member. This stops a random peer who guessed
        # a group_id from rewriting our local view.
        if from_id not in group.members and from_id != group.creator:
            return

        # Apply the change locally (idempotent).
        if action == "add" and target not in group.members:
            try:
                group.add_member(target)
            except ValueError:
                return
        elif action == "remove" and target in group.members:
            group.remove_member(target)

        # Reconcile against the sender's authoritative list.
        # Trust the sender's list as the new ground truth (eventual
        # consistency: last writer wins). We've already authorized
        # the sender above.
        group.members = list(members_list)

        self._notify_group_member_change(
            from_id, group_id, action, target, list(group.members))

    async def _fanout_group_member_change(
            self, group: "Group", action: str, target: str,
            exclude: set[str] | None = None) -> None:
        """Send a `group_member_change` to every member of `group`
        except ourselves and any peers in `exclude` (typically the
        target itself for a removal: we don't tell the removed
        member they're being removed via the group's own channel —
        they have their own pairwise relationship)."""
        ex = exclude or set()
        for m in group.members:
            if m == self.identity.peer_id:
                continue
            if m in ex:
                continue
            extras = {
                "group_id": group.group_id,
                "group_name": group.name,
                "action": action,
                "target": target,
                "members": list(group.members),
            }
            await self._try_send_payload(m, KIND_GROUP_MEMBER_CHANGE, extras)

    async def _handle_group_msg(self, data: dict, from_id: str) -> None:
        """Receive a single pairwise copy of a group message."""
        group_id = data.get("group_id")
        group_name = data.get("group_name", "")
        content = data.get("content")
        if not isinstance(group_id, str) or not isinstance(content, str):
            return
        # The application does not require us to be in the local group
        # registry — we can also display a message from a group we
        # haven't been formally invited to, which mirrors how a peer-to-
        # peer message from a known contact is delivered without prior
        # registration. But we do require the sender to be known
        # (already enforced by _dispatch_kind / _resolve_sealed_from
        # upstream).
        self._notify_group_message(from_id, group_id, str(group_name), content)
        # Optionally store in the conversation log.
        msg_id = data.get("msg_id")
        if isinstance(msg_id, str) and msg_id:
            self.store.store(from_id, self.identity.peer_id,
                             f"[group {group_name or group_id[:8]}] {content}", msg_id)

    async def create_group(self, name: str, members: list[str]) -> str | None:
        """Create a group and broadcast a group_invite to every member.

        Returns the group_id, or None if creation failed (name
        collision or a member that's not in the routing table).
        """
        for m in members:
            if not self.discovery.get_peer(m):
                return None
        try:
            group = self._groups.create(name, self.identity.peer_id, members)
        except ValueError:
            return None

        invite_extras = {
            "group_id": group.group_id,
            "group_name": group.name,
            "members": list(group.members),
        }
        for m in members:
            await self._try_send_payload(m, KIND_GROUP_INVITE, invite_extras)

        return group.group_id

    async def add_group_member(self, group_id: str, peer_id: str) -> bool:
        """Add a peer to an existing group, send them a `group_invite`,
        and notify all existing members via `group_member_change` so
        their fanouts pick up the new peer.

        Eventual-consistency model: the receiver of the
        `member_change` last-writer-wins reconciles its local
        membership against the sender's claimed list (PROTOCOL.md
        §10.2 + §13). We are explicitly NOT doing MLS-style
        cryptographic membership consensus (TM-01); see
        THREAT_MODEL.md.
        """
        group = self._groups.get_by_id(group_id)
        if group is None:
            return False
        if peer_id in group.members:
            return True  # idempotent
        if not self.discovery.get_peer(peer_id):
            return False
        try:
            group.add_member(peer_id)
        except ValueError:
            return False
        invite_extras = {
            "group_id": group.group_id,
            "group_name": group.name,
            "members": list(group.members),
        }
        await self._try_send_payload(peer_id, KIND_GROUP_INVITE, invite_extras)
        # Tell the rest so they include the new peer in fanouts.
        await self._fanout_group_member_change(
            group, action="add", target=peer_id,
            exclude={peer_id},   # the new joiner already got an invite
        )
        return True

    async def remove_group_member(self, group_id: str, peer_id: str) -> bool:
        """Remove `peer_id` from a group and notify the remaining
        members. The removed peer is NOT notified through the group
        channel (their own send pipeline doesn't get a hint either —
        deliberate: see THREAT_MODEL.md TM-01)."""
        group = self._groups.get_by_id(group_id)
        if group is None:
            return False
        if peer_id not in group.members:
            return True   # idempotent
        if peer_id == self.identity.peer_id:
            # Use leave_group for "remove yourself".
            return False
        group.remove_member(peer_id)
        await self._fanout_group_member_change(
            group, action="remove", target=peer_id,
            exclude={peer_id},
        )
        return True

    async def send_group_message(self, group_id: str, content: str) -> bool:
        """Pairwise fanout of `content` to every other member of the group.

        Returns True if at least one copy was successfully shipped.
        """
        group = self._groups.get_by_id(group_id)
        if group is None:
            return False
        any_ok = False
        for m in group.members:
            if m == self.identity.peer_id:
                continue
            extras = {
                "group_id": group.group_id,
                "group_name": group.name,
                "content": content,
            }
            ok = await self._try_send_payload(m, KIND_GROUP_MSG, extras)
            if ok:
                any_ok = True
        # Echo to local store so /history shows our outgoing.
        if any_ok:
            self.store.store(
                self.identity.peer_id,
                f"group:{group.group_id}",
                f"[group {group.name}] {content}",
                secrets.token_hex(16),
            )
        return any_ok

    def leave_group(self, group_id: str) -> bool:
        """Synchronous local-only departure (kept for backwards
        compatibility with existing callers and tests). Other
        members are NOT notified — use `leave_group_async` for the
        polite version that fans out a `group_member_change`."""
        group = self._groups.get_by_id(group_id)
        if group is None:
            return False
        self._groups.remove(group_id)
        return True

    async def leave_group_async(self, group_id: str) -> bool:
        """Leave a group and notify the remaining members so their
        future fanouts skip us. After the notification, we drop the
        group from our local registry."""
        group = self._groups.get_by_id(group_id)
        if group is None:
            return False
        # Update our view first so the fanout doesn't include us in
        # `members`. The remaining peers will see action=remove,
        # target=<self>, and adjust accordingly.
        if self.identity.peer_id in group.members:
            group.remove_member(self.identity.peer_id)
        await self._fanout_group_member_change(
            group, action="remove", target=self.identity.peer_id,
        )
        self._groups.remove(group_id)
        return True

    async def resume_file(self, dest_peer_id: str, file_id: str) -> str | None:
        """Re-send a previously-started file using its existing OutgoingFile.

        The receiver, if still holding a partial buffer for this
        `file_id`, will reply with a `file_resume` listing the chunk
        indices it already has, and the sender skips those.

        Returns the file_id on success, None if the OutgoingFile is
        not in the local registry (already cancelled or never sent
        from this process).
        """
        of = self._files.get_outgoing(file_id)
        if of is None:
            return None
        # The path is captured inside OutgoingFile, so send_file with
        # file_id=file_id will reuse it.
        return await self.send_file(dest_peer_id, path="", file_id=file_id)

    async def send_file(
        self,
        dest_peer_id: str,
        path: str,
        file_id: str | None = None,
    ) -> str | None:
        """Send a file to dest_peer_id. Returns file_id if started, None otherwise.

        If `file_id` is provided AND already exists in our outgoing
        registry, this is a resume: we re-use that OutgoingFile and
        let the receiver tell us via `file_resume` which chunks to
        skip. If `file_id` is provided but unknown, we fall back to
        treating it as a fresh send.
        """
        if file_id is not None:
            existing = self._files.get_outgoing(file_id)
            if existing is not None:
                of = existing
            else:
                try:
                    of = OutgoingFile(path)
                except (FileNotFoundError, ValueError, OSError):
                    return None
                self._files.register_outgoing(of)
                file_id = of.file_id
        else:
            try:
                of = OutgoingFile(path)
            except (FileNotFoundError, ValueError, OSError):
                return None
            file_id = self._files.register_outgoing(of)

        if not self.discovery.get_peer(dest_peer_id):
            return None
        offer = of.offer()

        # Resume protocol: arm an Event to receive the skip set, if any.
        resume_event = asyncio.Event()
        self._resume_events[file_id] = resume_event
        self._resume_signals.pop(file_id, None)

        # Phase 1: send offer
        ok = await self._try_send_payload(dest_peer_id, KIND_FILE_OFFER, offer.to_dict())
        if not ok:
            self._files.cancel(file_id)
            self._resume_events.pop(file_id, None)
            return None

        # Wait briefly for a file_resume from the receiver. If none
        # arrives within the window, the receiver had no partial
        # buffer for this file_id (or is a 0.7.x peer): proceed with
        # a full send.
        try:
            await asyncio.wait_for(resume_event.wait(), timeout=0.3)
        except asyncio.TimeoutError:
            pass
        skip = self._resume_signals.get(file_id, set())
        self._resume_events.pop(file_id, None)
        # Keep _resume_signals around in case the user retries again.

        # Phase 2: stream chunks (skipping resumed ones)
        import base64
        for idx, blob in of.chunkify():
            if idx in skip:
                continue
            extras = {
                "file_id": file_id,
                "chunk_idx": idx,
                "data_b64": base64.b64encode(blob).decode("ascii"),
            }
            sent = await self._try_send_payload(dest_peer_id, KIND_FILE_CHUNK, extras)
            if not sent:
                # peer dropped mid-transfer — bail out, application can retry
                return file_id
            # Small spacing keeps event loop responsive on big files
            await asyncio.sleep(0.005)
        return file_id

    async def _try_send_payload(
        self, dest_peer_id: str, kind: str, extras: dict
    ) -> bool:
        """
        Generalized version of _try_send: build a JSON payload of any kind,
        authenticate it (ratchet → HMAC → Ed25519), pad, onion-wrap, and ship
        it through a freshly selected circuit.
        """
        try:
            circuit = self.discovery.select_relay_circuit(dest_peer_id, hops=3)
        except ValueError:
            return False

        dest_peer = self.discovery.get_peer(dest_peer_id)
        if dest_peer is None:
            return False
        from_eph, from_sealed = seal_from(self.identity.peer_id, dest_peer.x25519_pub)

        msg_id = secrets.token_hex(16)
        nonce = secrets.token_bytes(16)
        payload_dict = {
            "kind": kind,
            "from_eph": from_eph,
            "from_sealed": from_sealed,
            "msg_id": msg_id,
            "nonce": nonce.hex(),
            "ts": time.time(),
            **extras,
        }
        payload_bytes = json.dumps(payload_dict).encode()

        dest_conn = self._connections.get(dest_peer_id)
        authenticated = _wrap_authenticated(
            payload_bytes, dest_conn, self.identity
        )

        padded = pad_payload(authenticated)
        packet = wrap_onion(padded, circuit)

        first_hop_id = circuit[0][1]
        conn = self._connections.get(first_hop_id)
        if conn and conn.authenticated:
            await conn.send_encrypted(MSG_ONION, packet[24:])
            return True
        return False

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

            # Sign ephemeral pubkey with our Ed25519 identity key
            # This proves we hold the private key for our claimed identity
            eph_sig = self.identity.sign(eph_pub)

            hello = json.dumps({
                "v": WIRE_VERSION,
                "eph_pub": eph_pub.hex(),
                "eph_sig": eph_sig.hex(),
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

            # Wire-version check. Lenient on missing (pre-1.0.0-rc1
            # peers don't send it); strict on mismatch (a future
            # bump means the protocol changed, refuse to talk).
            their_v = their_data.get("v")
            if their_v is not None and their_v != WIRE_VERSION:
                return False

            their_eph = bytes.fromhex(their_data["eph_pub"])
            their_eph_sig = bytes.fromhex(their_data["eph_sig"])
            their_x25519 = bytes.fromhex(their_data["x25519_pub"])
            their_ed25519 = bytes.fromhex(their_data["ed25519_pub"])
            their_peer_id = their_data["peer_id"]
            their_port = their_data.get("port", self.port)

            # Verify the peer's Ed25519 signature over their ephemeral key.
            # Without this, a MITM could present their own ephemeral key
            # and intercept the entire session.
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            try:
                peer_ed_pub = Ed25519PublicKey.from_public_bytes(their_ed25519)
                peer_ed_pub.verify(their_eph_sig, their_eph)
            except Exception:
                return False  # signature invalid — reject handshake

            # Key pinning (TOFU): verify Ed25519 key matches the pinned key
            # for this peer_id. First contact pins the key; subsequent contacts
            # must match or the handshake is rejected.
            ok, pinned = self.pins.check_and_pin(their_peer_id, their_ed25519)
            if not ok:
                for cb in self._pin_callbacks:
                    try:
                        cb(their_peer_id, pinned, their_ed25519.hex())
                    except Exception:
                        pass
                return False  # key mismatch — reject

            shared = ecdh_shared_secret(eph_priv, their_eph)
            role = "initiator" if outbound else "responder"
            session_key = derive_session_key(shared, eph_pub, their_eph, role)

            conn.session_key = session_key
            conn.hmac_key = derive_hmac_key(session_key)
            conn.ratchet = RatchetState.from_shared_secret(
                shared, eph_priv, their_eph, is_initiator=outbound
            )
            conn.authenticated = True

            host = conn.writer.get_extra_info("peername")[0]
            peer = self.discovery.add_peer(
                their_peer_id, host, their_port, their_x25519, their_ed25519
            )
            conn.peer_info = peer
            return True
        except Exception:
            return False

    # ── Auto-reconnect ────────────────────────────────────────────────────────

    def set_reconnect_book(self, book) -> None:
        """Set the address book to enable auto-reconnect for known peers."""
        self._reconnect_book = book

    async def _reconnect(self, contact) -> None:
        """
        Reconnect to a peer with exponential backoff + jitter.

        Jitter (±20%) avoids the thundering-herd pattern where many
        peers behind the same NAT/AP retry in lockstep when the network
        comes back, swamping the gateway.
        """
        peer_id = contact.peer_id
        if peer_id in self._reconnect_tasks:
            return  # already reconnecting

        import secrets as _secrets
        rng = _secrets.SystemRandom()

        delay = 5  # initial delay in seconds
        max_delay = 300  # 5 minutes cap

        try:
            self._reconnect_tasks[peer_id] = asyncio.current_task()
            while self._running and peer_id not in self._connections:
                # Apply ±20% jitter to the planned delay
                jitter_factor = 1.0 + (rng.random() - 0.5) * 0.4
                jittered = max(0.1, delay * jitter_factor)
                await asyncio.sleep(jittered)
                if not self._running:
                    break
                ok = await self.connect_to_peer(
                    contact.host, contact.port, contact.peer_id,
                    bytes.fromhex(contact.x25519_pub),
                    bytes.fromhex(contact.ed25519_pub),
                )
                if ok:
                    break
                delay = min(delay * 2, max_delay)
        except (asyncio.CancelledError, Exception):
            pass
        finally:
            self._reconnect_tasks.pop(peer_id, None)

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

        # Wipe key pins
        self.pins.wipe()

        # Wipe replay cache
        self._replay.wipe()

        # Wipe in-flight file transfers
        self._files.wipe()
        self._resume_signals.clear()
        for ev in self._resume_events.values():
            ev.set()  # unblock any waiting send_file()
        self._resume_events.clear()
        self._groups.wipe()

        # Wipe message queue
        self._message_queue.clear()

        # Cancel all reconnect tasks
        for task in list(self._reconnect_tasks.values()):
            task.cancel()
        self._reconnect_tasks.clear()
        self._reconnect_book = None

        # Wipe ratchet states
        for conn in self._connections.values():
            if hasattr(conn, 'ratchet'):
                conn.ratchet = None

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
            self._replay.purge_expired()

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
