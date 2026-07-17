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
import hmac
import json
import logging
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
from .groups import MAX_MEMBERS, MAX_NAME_LEN, Group, GroupRegistry
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

# Diagnostic logger. No handler is attached by default (the privacy stance
# is: nothing on disk), so this is silent unless `--debug` wires a stderr
# handler onto the `malphas` logger. It exists so silent fail-closed drops
# (auth failures, dropped frames, queued-not-sent) are observable when you
# explicitly opt in, instead of vanishing.
logger = logging.getLogger(__name__)

# Wire-protocol version. Bumped when the byte-level layout of anything in
# PROTOCOL.md sections 4-9 changes. Bumped 1 -> 2 at `1.0.0-rc7` for the
# security-audit fixes already implemented below (eph_sig covers the static
# X25519 key, both keys pinned, ratchet header bound as AAD). This constant
# is the single source of truth and must equal `malphas.WIRE_VERSION`;
# further changes go through the additive-only rules in PROTOCOL.md §10.
WIRE_VERSION = 2

# Wire message types
MSG_HANDSHAKE     = 0x01
MSG_HANDSHAKE_ACK = 0x02
MSG_ONION         = 0x03
MSG_PING          = 0x05
MSG_PONG          = 0x06
MSG_PEER_ANNOUNCE = 0x07

HEADER_LEN = 5   # type(1) + length(4)
# Hard ceiling on a single wire frame body. The length field is an
# unsigned 32-bit int (max ~4 GiB); without a cap a peer can send a 5-byte
# header announcing a 4 GiB body and force the reader to buffer it, OOM-
# killing the process pre-authentication. PROTOCOL.md §4 already specifies
# this 16 MiB limit — it just wasn't enforced.
MAX_FRAME_BYTES = 16 * 1024 * 1024
# Tighter cap for pre-authentication handshake frames. A legitimate hello is
# ~500 bytes; there is no reason to let an unauthenticated peer announce a
# 16 MiB body before it has proven anything. Bounding the handshake read
# shrinks the pre-auth buffering an attacker can force per connection.
HANDSHAKE_MAX_FRAME_BYTES = 8 * 1024
# Cap on simultaneous inbound connections (incl. in-flight handshakes). An
# unbounded accept loop lets an attacker exhaust file descriptors / tasks and
# inflate the O(connections) ratchet trial-decrypt. Outbound (user-initiated)
# connections are not counted against this.
MAX_INBOUND_CONNECTIONS = 128
# Idle timeout for an authenticated read loop (seconds). A peer that sends a
# partial frame and then stalls (slowloris) would otherwise pin a task and its
# buffer forever; cover traffic / pings on a live link arrive well inside this.
_READ_IDLE_TIMEOUT = 300
# Upper bound on a file-resume `received_idx` list. We only ever send files
# chunked at files.CHUNK_SIZE (32 KB), so a 100 MB file is ~3200 chunks; this
# bounds the set comprehension that materialises the list so a peer can't ship
# millions of integers to burn CPU on the event-loop thread.
_MAX_RESUME_INDICES = 8192
# Freshness window for the per-payload `ts` field (seconds). A message may
# arrive up to _TS_FUTURE_SKEW in the "future" (peer clock ahead) and up to
# _TS_PAST_WINDOW in the past (peer clock behind / brief queueing) before we
# treat it as a replayed capture and drop it.
_TS_FUTURE_SKEW = 300
_TS_PAST_WINDOW = 3600

# Authentication-type prefix on the inner authenticated payload
# (post-onion-peel, post-padding-strip). Exactly one byte; the receiver
# dispatches on this byte to pick the right authentication path.
# Wire format introduced in v0.4.0 — older clients (<= 0.3.x) won't be
# able to decode messages from new clients and vice-versa.
AUTH_RATCHET = b"R"   # b"R" || header(40) || ratchet ciphertext
AUTH_HMAC    = b"H"   # b"H" || tag(32)    || JSON payload bytes
AUTH_ED25519 = b"E"   # b"E" || sig(64)    || JSON payload bytes
# b"X" || IK_A(32) || EK_A(32) || SPK_B(32) || OPK_B(32) || header(40) || ct
# X3DH session opener (issue #12): forward-secret + deniable delivery to a peer
# we are not directly connected to. IK_A/EK_A are the sender's identity and
# ephemeral X25519 pubs; SPK_B is which signed prekey was used; OPK_B is the
# one-time prekey used (all-zeros = none, SPK-only). Visible only to the final
# recipient (inside the innermost onion layer).
AUTH_X3DH    = b"X"

HMAC_TAG_LEN     = 32
ED25519_SIG_LEN  = 64
RATCHET_HEADER_LEN = 40
X3DH_HEADER_LEN  = 128  # IK_A(32) || EK_A(32) || SPK_B(32) || OPK_B(32)
# Number of one-time prekeys minted per node (published in the invite).
N_ONE_TIME_PREKEYS = 32
_ZERO_OPK = b"\x00" * 32  # OPK_B sentinel meaning "no one-time prekey used"

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

    async def recv_raw(self, max_bytes: int = MAX_FRAME_BYTES) -> tuple:
        header = await self.reader.readexactly(HEADER_LEN)
        msg_type, length = _unpack_header(header)
        if length is None or length > max_bytes:
            raise ConnectionError(
                f"frame length {length} exceeds {max_bytes} cap"
            )
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
        self._inflight_inbound = 0   # active inbound conns incl. handshakes
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

        # X3DH (issue #12): a per-node signed prekey, published in invites, lets
        # peers open a forward-secret, deniable session with us when they are
        # not directly connected (multi-hop delivery). Sessions are one-way
        # ratchets keyed by peer_id: initiator sessions for what we send,
        # responder sessions for what we receive.
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey as _X25519PrivateKey,
        )

        from .prekey import generate_signed_prekey
        self._spk_priv, self.signed_prekey_pub, self.signed_prekey_sig = (
            generate_signed_prekey(identity.ed25519_priv))
        # One-time prekeys (issue #12 hardening): a batch of single-use X25519
        # keys published in the invite. Mixing one into X3DH and DELETING its
        # private after use gives the first message forward secrecy even against
        # a later compromise of our identity + signed prekey. Optional: when the
        # batch is exhausted, senders fall back to SPK-only X3DH.
        self._opk_privs: dict[bytes, _X25519PrivateKey] = {}
        for _ in range(N_ONE_TIME_PREKEYS):
            _p = _X25519PrivateKey.generate()
            self._opk_privs[_p.public_key().public_bytes_raw()] = _p
        self.one_time_prekeys_pub: list[bytes] = list(self._opk_privs.keys())
        self._x3dh_send_sessions: dict[str, RatchetState] = {}
        self._x3dh_recv_sessions: dict[str, RatchetState] = {}

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
        # Close peer connections FIRST, then the transport. transport.stop()
        # awaits the listening server's wait_closed(), which blocks until
        # every in-flight inbound connection handler (_handle_incoming →
        # _read_loop) returns. Those handlers only return once their socket
        # sees EOF — i.e. once we close our side here. Doing it in the old
        # order (transport.stop() before conn.close()) deadlocked shutdown
        # for ~30s whenever a peer was connected.
        for conn in list(self._connections.values()):
            conn.close()
        self._connections.clear()
        await self.transport.stop()
        await self.discovery.stop_mdns()
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
            ok = await self._perform_handshake(
                conn, outbound=True,
                expected_peer=(peer_id, ed25519_pub, x25519_pub),
            )
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
            logger.debug("message to %s queued (not connected / no circuit yet)",
                         dest_peer_id[:8])
            self._enqueue(dest_peer_id, content, msg_id)
            self.store.store(self.identity.peer_id, dest_peer_id, content, msg_id)
            return msg_id

        logger.debug("send to %s failed: peer unknown", dest_peer_id[:8])
        return None

    def _relay_pool(self) -> set[str]:
        """peer_ids we have a live, authenticated connection to.

        Onion circuits may only relay through these: the first hop is sent
        over an existing connection, so relaying through a peer we aren't
        connected to silently drops the message.
        """
        return {
            pid for pid, conn in self._connections.items()
            if conn.authenticated
        }

    async def forget_peer(self, peer_id: str) -> None:
        """Disconnect and fully forget a peer.

        Closes the live connection, drops the peer from the routing/discovery
        table (so it can no longer be picked as a relay or a circuit
        destination), cancels any pending reconnect, and discards queued
        messages for it. The encrypted address-book entry is the caller's
        responsibility (it lives outside the node).
        """
        conn = self._connections.pop(peer_id, None)
        if conn is not None:
            conn.close()
        self.discovery.table.remove(peer_id)
        task = self._reconnect_tasks.pop(peer_id, None)
        if task is not None:
            task.cancel()
        self._message_queue.pop(peer_id, None)

    def _wrap_for_dest(
        self, payload_bytes: bytes, dest_peer_id: str, dest_peer: "PeerInfo | None"
    ) -> bytes:
        """
        Authenticate/encrypt `payload_bytes` for a destination, strongest first.

        1. Live connection with a ratchet -> Double Ratchet (AUTH_RATCHET).
        2. Live connection pre-ratchet     -> HMAC (AUTH_HMAC).
        3. Not connected but we know the peer's signed prekey -> X3DH: a
           forward-secret, deniable session (AUTH_X3DH to open, AUTH_RATCHET to
           continue). This replaces the old non-forward-secret Ed25519 fallback.
        4. Otherwise (no SPK, e.g. a peer imported via an old invite) -> the
           legacy Ed25519 signature fallback.
        """
        dest_conn = self._connections.get(dest_peer_id)
        if dest_conn and dest_conn.ratchet and dest_conn.ratchet._send_chain_key:
            header, ciphertext = dest_conn.ratchet.encrypt(payload_bytes)
            return AUTH_RATCHET + header.serialize() + ciphertext
        if dest_conn and dest_conn.hmac_key:
            return AUTH_HMAC + hmac_sign(dest_conn.hmac_key, payload_bytes) + payload_bytes
        if dest_peer is not None and dest_peer.spk_pub is not None:
            return self._wrap_x3dh(payload_bytes, dest_peer_id, dest_peer)
        return AUTH_ED25519 + self.identity.sign(payload_bytes) + payload_bytes

    def _wrap_x3dh(
        self, payload_bytes: bytes, dest_peer_id: str, dest_peer: "PeerInfo"
    ) -> bytes:
        """Open or advance a forward-secret X3DH session to `dest_peer`."""
        from .prekey import x3dh_initiator

        session = self._x3dh_send_sessions.get(dest_peer_id)
        if session is not None and session._send_chain_key:
            # Session already established: advance the ratchet.
            header, ciphertext = session.encrypt(payload_bytes)
            return AUTH_RATCHET + header.serialize() + ciphertext

        # Fresh session: X3DH with the peer's signed prekey, seed the ratchet
        # as initiator (the peer's SPK is the initial ratchet key). If the peer
        # published one-time prekeys, consume one for stronger first-message
        # forward secrecy; otherwise fall back to SPK-only (OPK_B = zeros).
        assert dest_peer.spk_pub is not None
        opk_pub = None
        if dest_peer.opks:
            opk_pub = dest_peer.opks.pop()  # one-time: don't reuse it locally
        sk, ek_pub = x3dh_initiator(
            self.identity.x25519_priv, dest_peer.x25519_pub, dest_peer.spk_pub,
            their_opk_pub=opk_pub)
        ratchet = RatchetState.from_shared_secret(
            sk, our_dh_priv=self.identity.x25519_priv,
            remote_dh_pub=dest_peer.spk_pub, is_initiator=True)
        self._x3dh_send_sessions[dest_peer_id] = ratchet
        header, ciphertext = ratchet.encrypt(payload_bytes)
        return (AUTH_X3DH + self.identity.x25519_pub_bytes + ek_pub
                + dest_peer.spk_pub + (opk_pub or _ZERO_OPK)
                + header.serialize() + ciphertext)

    async def _try_send(self, dest_peer_id: str, content: str, msg_id: str) -> bool:
        """Attempt to send a message immediately. Returns True if sent."""
        try:
            circuit = self.discovery.select_relay_circuit(
                dest_peer_id, hops=3, relay_pool=self._relay_pool())
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
            "ts": int(time.time()),  # int secs; sub-second would leak clock-skew
        }
        payload_bytes = json.dumps(payload_dict).encode()

        authenticated = self._wrap_for_dest(payload_bytes, dest_peer_id, dest_peer)

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
        """Send all queued messages for a peer after reconnection.

        A send that fails mid-flush (circuit/connection dropped again) is
        re-queued rather than silently dropped, so the message survives to the
        next reconnect instead of being lost.
        """
        queue = self._message_queue.pop(peer_id, [])
        for content, msg_id in queue:
            ok = await self._try_send(peer_id, content, msg_id)
            if not ok:
                self._enqueue(peer_id, content, msg_id)
            await asyncio.sleep(0.05)  # avoid flooding

    async def _send_cover_packet(self, peer_id: str) -> None:
        """Send a cover-traffic packet, routed exactly like a real message.

        Cover packets must be indistinguishable from real ones on the wire.
        A real message uses a 3-hop onion circuit (see _try_send); a 1-hop
        cover packet is smaller (fewer onion layers) and is delivered rather
        than relayed at the first hop, which leaks which packets are cover.
        Build the same 3-hop circuit here; if we cannot (not enough relays),
        skip rather than emit a distinguishable short packet.
        """
        try:
            circuit = self.discovery.select_relay_circuit(
                peer_id, hops=3, relay_pool=self._relay_pool())
        except ValueError:
            return

        cover_payload = make_cover_payload()
        packet = wrap_onion(cover_payload, circuit)

        first_hop_id = circuit[0][1]
        conn = self._connections.get(first_hop_id)
        if conn and conn.authenticated:
            try:
                await conn.send_encrypted(MSG_ONION, packet[24:])
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
        authenticated = self._wrap_for_dest(payload_bytes, from_id, dest_peer)
        padded = pad_payload(authenticated)

        # Route back to sender if we have them in routing table
        try:
            circuit = self.discovery.select_relay_circuit(
                from_id, hops=3, relay_pool=self._relay_pool())
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
        # Reject early if we're already at the inbound cap — before doing any
        # handshake work — so a connection flood can't exhaust fds/tasks.
        if self._inflight_inbound >= MAX_INBOUND_CONNECTIONS:
            try:
                writer.close()
            except Exception:  # noqa: S110
                pass
            return
        self._inflight_inbound += 1
        try:
            conn = PeerConnection(reader, writer)
            ok = await self._perform_handshake(conn, outbound=False)
            if ok and conn.peer_info:
                self._connections[conn.peer_info.peer_id] = conn
                await self._read_loop(conn)
            else:
                conn.close()
        finally:
            self._inflight_inbound -= 1

    def _forget_connection_if_current(self, conn: PeerConnection) -> str | None:
        """Drop `conn` from the connection table, but only if it is still the
        current connection for its peer_id.

        Guards the duplicate-connection race: if a newer connection has already
        replaced this one under the same peer_id (reconnect, or a second dial),
        an unconditional `pop(peer_id)` from this connection's ended read loop
        would evict the *newer, live* connection. Returns the peer_id (for
        reconnect scheduling) regardless of whether anything was removed.
        """
        peer_id = conn.peer_info.peer_id if conn.peer_info else None
        if peer_id and self._connections.get(peer_id) is conn:
            self._connections.pop(peer_id, None)
        return peer_id

    async def _read_loop(self, conn: PeerConnection) -> None:
        try:
            while self._running:
                # Idle timeout: a stalled/partial-frame peer (slowloris) must
                # not hold this task and its buffer open indefinitely.
                msg_type, payload = await asyncio.wait_for(
                    conn.recv_raw(), timeout=_READ_IDLE_TIMEOUT
                )
                await self._dispatch(conn, msg_type, payload)
        except (asyncio.IncompleteReadError, ConnectionResetError, OSError, Exception):
            pass
        finally:
            peer_id = self._forget_connection_if_current(conn)
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

            # Trial-decrypt across each connection's ratchet AND each
            # established X3DH responder session (issue #12). State is
            # snapshotted before each attempt so a wrong-session try cannot
            # corrupt the receiver-state of the right one.
            candidates = [
                (pid, conn.ratchet)
                for pid, conn in list(self._connections.items())
                if conn.ratchet
            ]
            candidates += list(self._x3dh_recv_sessions.items())
            for _peer_id, ratchet in candidates:
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

                # Bind the sender identity to the authenticated session.
                # The ratchet only proves "the peer on THIS connection sent
                # this"; the sealed `from_id` is sealed to OUR public key and
                # is therefore attacker-chosen. Without this check, any peer
                # with a ratchet session could impersonate any other peer by
                # sealing their id. `_peer_id` is the handshake-authenticated
                # identity of the connection (peer_id == BLAKE2s(ed25519_pub),
                # enforced in _perform_handshake).
                if from_id != _peer_id:
                    logger.debug(
                        "dropped ratchet msg: sealed from_id %s != connection peer %s",
                        from_id[:8], _peer_id[:8])
                    _restore_ratchet(ratchet, snap)
                    return

                peer = self.discovery.get_peer(from_id)
                if not peer:
                    _restore_ratchet(ratchet, snap)
                    continue

                await self._dispatch_kind(data, from_id, peer)
                return
            # No ratchet could decrypt — drop
            logger.debug("dropped ratchet frame: no connection ratchet decrypted it")
            return

        if prefix == AUTH_X3DH:
            await self._handle_x3dh_open(signed)
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
            logger.debug("dropped frame from unknown sender %s",
                         from_id[:8] if from_id else "?")
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

    async def _handle_x3dh_open(self, signed: bytes) -> None:
        """Open a forward-secret X3DH responder session (issue #12) and deliver
        the first message. `signed` = X || IK_A(32) || EK_A(32) || SPK_B(32) ||
        OPK_B(32) || ratchet_header(40) || ratchet_ciphertext."""
        if len(signed) <= 1 + X3DH_HEADER_LEN + RATCHET_HEADER_LEN:
            return
        ik_a = signed[1:33]
        ek_a = signed[33:65]
        spk_b = signed[65:97]
        opk_b = signed[97:129]
        header_bytes = signed[129:129 + RATCHET_HEADER_LEN]
        ciphertext = signed[129 + RATCHET_HEADER_LEN:]

        # Only our current signed prekey is supported (no SPK rotation history).
        if not hmac.compare_digest(spk_b, self.signed_prekey_pub):
            return

        # Resolve the one-time prekey the sender used. All-zeros = none. A
        # non-zero OPK we no longer hold was already consumed (or is invalid):
        # drop, which also gives one-time replay protection. Do NOT delete it
        # yet; only after the message fully validates, so an unknown peer
        # cannot exhaust our OPK pool by replaying valid public OPKs.
        opk_priv = None
        if opk_b != _ZERO_OPK:
            opk_priv = self._opk_privs.get(opk_b)
            if opk_priv is None:
                return

        from .prekey import x3dh_responder
        try:
            sk = x3dh_responder(
                self.identity.x25519_priv, self._spk_priv, ik_a, ek_a,
                my_opk_priv=opk_priv)
            ratchet = RatchetState.from_shared_secret(
                sk, our_dh_priv=self._spk_priv,
                remote_dh_pub=self.signed_prekey_pub, is_initiator=False)
            header = MessageHeader.deserialize(header_bytes)
            payload_bytes = ratchet.decrypt(header, ciphertext)
        except Exception:
            return

        try:
            data = json.loads(payload_bytes.decode())
        except Exception:
            return

        from_id = _resolve_sealed_from(data, self.identity.x25519_priv)
        kind = data.get("kind")
        if not from_id or not kind:
            return

        # Bind: the sealed sender must be a known peer whose static X25519 key
        # equals the IK_A used in the X3DH, or a peer could open a session
        # under someone else's identity key.
        peer = self.discovery.get_peer(from_id)
        if not peer or not hmac.compare_digest(peer.x25519_pub, ik_a):
            return

        # Fully validated: consume the one-time prekey (delete its private so it
        # can never be reused) for first-message forward secrecy.
        if opk_priv is not None:
            self._opk_privs.pop(opk_b, None)

        # Keep the responder session so subsequent AUTH_RATCHET frames advance it.
        self._x3dh_recv_sessions[from_id] = ratchet
        await self._dispatch_kind(data, from_id, peer)

    async def _dispatch_kind(
        self, data: dict, from_id: str, peer: PeerInfo | None
    ) -> None:
        """Single dispatch site for all message kinds, with replay guard."""
        kind = data.get("kind")
        msg_id = data.get("msg_id", "")

        # Freshness window. Every real transmission stamps `ts` = time.time()
        # at send (re-stamped on each retry), so a legitimate message — even
        # a delayed/offline one — is always near-current. A stale `ts` means
        # a captured packet replayed by a relay/recorder; reject it. This
        # complements the replay cache (which only remembers ~1h / 10k ids).
        # `ts` is optional for backward compat; clock skew is tolerated.
        ts = data.get("ts")
        if isinstance(ts, (int, float)):
            now = time.time()
            if ts > now + _TS_FUTURE_SKEW or ts < now - _TS_PAST_WINDOW:
                return

        # Replay protection across every kind (msg, receipt, file_*, group_*).
        # Cover packets carry no msg_id and are dropped before reaching here,
        # so every real payload that arrives MUST have one (every sender stamps
        # it in _try_send_payload). Treat a missing/empty msg_id as malformed
        # and drop it — otherwise file_offer/group_invite, which don't re-check
        # msg_id downstream, would slip past the replay guard (notification
        # flooding).
        if not msg_id or self._replay.seen(from_id, msg_id):
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
        # Pass from_id so the tracker can verify the receipt actually came
        # from the message's destination (peer is get_peer(from_id), so its
        # key is the destination's pinned key). Stops forged receipts from
        # any other contact who learns the msg_id.
        self.receipts.resolve(msg_id, sig, pub, from_peer_id=from_id)

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
            # Already registered — notify, and immediately tell the sender
            # we're ready so it streams the chunks (the sender waits for this).
            self._notify_file_offer(from_id, offer_dict)
            await self.send_file_resume(from_id, offer.file_id)
        else:
            # Default policy: do NOT register; require explicit accept. The
            # sender's resume wait will hold until the user accepts (which
            # then sends the file_resume).
            self._files.drop_incoming(offer.file_id)
            self._notify_file_offer(from_id, offer_dict)

    def accept_file_offer(self, offer_dict: dict) -> bool:
        """Application-level accept: register the incoming buffer.

        After this returns True the caller MUST call `send_file_resume` to
        tell the sender to start streaming chunks — see send_file()'s resume
        wait. Without it, a manually-accepted file never arrives (the sender
        blasted the chunks right after the offer, before the buffer existed).
        """
        try:
            offer = FileOffer.from_dict(offer_dict)
            self._files.register_incoming(offer)
            return True
        except (KeyError, ValueError):
            return False

    async def send_file_resume(self, from_id: str, file_id: str) -> None:
        """Signal the sender that we're ready to receive `file_id`.

        Sends a `file_resume` listing the chunk indices we already hold
        (empty on a fresh accept). This unblocks the sender's resume wait so
        it streams the chunks AFTER our buffer is registered — required for
        manual accept, where registration happens seconds after the offer.
        """
        ic = self._files.get_incoming(file_id)
        received = ic.received_indices() if ic is not None else []
        await self._try_send_payload(
            from_id, KIND_FILE_RESUME,
            {"file_id": file_id, "received_idx": received})

    async def _handle_file_chunk(self, data: dict, from_id: str) -> None:
        import base64
        file_id = data.get("file_id")
        chunk_idx = data.get("chunk_idx")
        data_b64 = data.get("data_b64")
        if not file_id or chunk_idx is None or not isinstance(data_b64, str):
            return
        ic = self._files.get_incoming(file_id)
        if ic is None:
            logger.debug("file chunk for %s dropped (not accepted / unknown)",
                         str(file_id)[:8])
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
        # Only honor resume signals for files we are actively sending — checked
        # BEFORE materialising the index set, so a peer can't burn CPU/memory
        # by sending millions of entries for a file we don't even have.
        if self._files.get_outgoing(file_id) is None:
            return
        # A file we send is chunked at CHUNK_SIZE (32 KB), so a 100 MB file has
        # at most ~3200 chunks; any longer index list is bogus.
        if len(received) > _MAX_RESUME_INDICES:
            return
        try:
            idx_set = {int(i) for i in received}
        except (TypeError, ValueError):
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
        # Bound peer-supplied strings on the receive path. GroupRegistry.create
        # enforces MAX_NAME_LEN locally, but register() (the receive path) did
        # not — an authenticated peer could otherwise send a 100 MB group_name
        # or group_id and have it stored in memory (per-invite heap DoS).
        if len(group_name) > MAX_NAME_LEN or len(group_id) > 128:
            return
        try:
            members_list = [str(m)[:64] for m in members]
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

        # Authorization. Previously any current member could authorize a
        # change AND the sender's full member list was trusted as ground
        # truth ("last writer wins"), so one malicious member could rewrite
        # the entire roster — add themselves anywhere, remove the creator.
        # Now: only the group CREATOR may add/remove others, and any peer
        # may remove ITSELF (a legitimate "leave"). Until a real
        # cryptographic membership scheme exists (PROTOCOL.md §13 / TM-01),
        # this is the defensible minimum.
        is_creator = (from_id == group.creator)
        is_self_leave = (action == "remove" and target == from_id)
        if not is_creator and not is_self_leave:
            return

        # Apply ONLY the single authorized delta. Do not replace the
        # roster with the sender-supplied `members` list (that was the
        # takeover vector). `members_list` is still validated above purely
        # to reject malformed payloads.
        if action == "add" and target not in group.members:
            try:
                group.add_member(target)
            except ValueError:
                return
        elif action == "remove" and target in group.members:
            group.remove_member(target)

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
        # Require the group to be locally known AND the sender to be a
        # current member. Previously any known contact could inject a
        # message into any group_id (or invent one), spoofing group
        # context. The legitimate flow always delivers a group_invite
        # first, so a real member's message arrives with the group
        # already registered and the sender in its member list.
        group = self._groups.get_by_id(group_id)
        if group is None or from_id not in group.members:
            return
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
        # Only the creator may mutate membership. Every peer's receive side
        # already rejects a `group_member_change` that is not from the creator
        # (see _handle_group_member_change), so a non-creator's local edit
        # would be applied here but refused by everyone else, forking the
        # group_id. Refuse it locally too.
        if group.creator != self.identity.peer_id:
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
        # Only the creator may mutate membership (see add_group_member);
        # otherwise a non-creator forks the group_id against everyone else.
        if group.creator != self.identity.peer_id:
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

        # Wait for the receiver's file_resume before streaming chunks. A
        # modern receiver sends it as soon as it has a buffer — immediately
        # on auto-accept, or when the user runs /accept (which can take
        # several seconds of human time, hence the generous timeout). If
        # none arrives (legacy peer, or rejected), fall through and send
        # anyway — harmless if the receiver has no buffer (chunks dropped).
        try:
            await asyncio.wait_for(resume_event.wait(), timeout=60.0)
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
            circuit = self.discovery.select_relay_circuit(
                dest_peer_id, hops=3, relay_pool=self._relay_pool())
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
            "ts": int(time.time()),  # int secs; sub-second would leak clock-skew
            **extras,
        }
        payload_bytes = json.dumps(payload_dict).encode()

        authenticated = self._wrap_for_dest(payload_bytes, dest_peer_id, dest_peer)

        padded = pad_payload(authenticated)
        packet = wrap_onion(padded, circuit)

        first_hop_id = circuit[0][1]
        conn = self._connections.get(first_hop_id)
        if conn and conn.authenticated:
            await conn.send_encrypted(MSG_ONION, packet[24:])
            return True
        return False

    async def _handle_peer_announce(self, payload: bytes) -> None:
        # DEPRECATED + DROPPED. This gossip message let an authenticated
        # peer inject arbitrary (peer_id, host, port, keys) tuples into our
        # routing table with no proof that peer_id == BLAKE2s(ed25519_pub).
        # That poisons relay selection and the peer_id->key map every auth
        # path trusts. Nothing in this codebase sends MSG_PEER_ANNOUNCE, so
        # we simply drop it. Peers are learned only via the authenticated
        # handshake (which binds peer_id to the key) or explicit invites.
        return

    # ── Handshake ─────────────────────────────────────────────────────────────

    async def _perform_handshake(
        self,
        conn: PeerConnection,
        outbound: bool,
        expected_peer: tuple[str, bytes, bytes] | None = None,
    ) -> bool:
        try:
            async def _send_our_hello() -> tuple:
                # Sign the ephemeral pubkey AND our static X25519 key with our
                # Ed25519 identity key: signing eph_pub proves we hold the
                # identity key; binding x25519_pub stops an on-path attacker
                # from swapping our static encryption key (which would redirect
                # every sealed-sender envelope for us to the attacker).
                eph_priv, eph_pub = generate_ephemeral_keypair()
                eph_sig = self.identity.sign(
                    eph_pub + self.identity.x25519_pub_bytes)
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
                    MSG_HANDSHAKE if outbound else MSG_HANDSHAKE_ACK, hello)
                return eph_priv, eph_pub

            async def _recv_and_validate_their_hello() -> tuple | None:
                expected_type = MSG_HANDSHAKE_ACK if outbound else MSG_HANDSHAKE
                msg_type, their_hello = await asyncio.wait_for(
                    conn.recv_raw(max_bytes=HANDSHAKE_MAX_FRAME_BYTES),
                    timeout=10.0)
                if msg_type != expected_type:
                    return None
                their_data = json.loads(their_hello.decode())
                # `v` is mandatory and must equal WIRE_VERSION.
                if their_data.get("v") != WIRE_VERSION:
                    return None
                t_eph = bytes.fromhex(their_data["eph_pub"])
                t_eph_sig = bytes.fromhex(their_data["eph_sig"])
                t_x25519 = bytes.fromhex(their_data["x25519_pub"])
                t_ed25519 = bytes.fromhex(their_data["ed25519_pub"])
                t_peer_id = their_data["peer_id"]
                t_port = their_data.get("port", self.port)
                # peer_id MUST be the BLAKE2s digest of the presented Ed25519
                # key (PROTOCOL.md §5), else peer_id is an attacker-chosen label.
                from .identity import peer_id_from_pubkey
                if t_peer_id != peer_id_from_pubkey(t_ed25519):
                    return None
                # Verify the Ed25519 signature over (their eph || their x25519).
                from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                    Ed25519PublicKey,
                )
                try:
                    Ed25519PublicKey.from_public_bytes(t_ed25519).verify(
                        t_eph_sig, t_eph + t_x25519)
                except Exception:
                    return None
                return t_eph, t_x25519, t_ed25519, t_peer_id, t_port

            # DoS hardening (#11): the responder reads and fully validates the
            # client hello BEFORE generating a key, signing, and replying — so
            # an unauthenticated peer cannot extract free ephemeral-keygen +
            # signature work (or our ephemeral/signature) per connection. The
            # initiator still sends first, then reads, so there is no deadlock
            # (initiator send -> responder recv -> responder send -> initiator recv).
            if outbound:
                eph_priv, eph_pub = await _send_our_hello()
                got = await _recv_and_validate_their_hello()
            else:
                got = await _recv_and_validate_their_hello()
                if got is None:
                    return False
                eph_priv, eph_pub = await _send_our_hello()
            if got is None:
                return False
            their_eph, their_x25519, their_ed25519, their_peer_id, their_port = got

            # Invite/dial authentication: when the caller told us WHICH peer we
            # meant to reach (from an invite or an address-book entry), the
            # endpoint must actually be that peer. Without this, the handshake
            # only proves the endpoint's identity is internally consistent, so
            # any peer answering the address could impersonate a "connected"
            # state under its own key and poison our pins. Compare before the
            # TOFU pin so a mismatched endpoint is never persisted.
            if expected_peer is not None:
                exp_peer_id, exp_ed25519, exp_x25519 = expected_peer
                if (
                    their_peer_id != exp_peer_id
                    or not hmac.compare_digest(their_ed25519, exp_ed25519)
                    or not hmac.compare_digest(their_x25519, exp_x25519)
                ):
                    return False  # endpoint is not the peer we intended to reach

            # Key pinning (TOFU): verify Ed25519 key matches the pinned key
            # for this peer_id. First contact pins the key; subsequent contacts
            # must match or the handshake is rejected.
            #
            # Persist the pin to disk only for peers we have a relationship
            # with: an outbound dial to a specific invited/book peer
            # (expected_peer set), or an inbound peer already in the address
            # book. Unknown inbound peers are pinned ephemerally (in memory,
            # capped) so a flood of fresh inbound identities cannot grow the
            # on-disk pin store without bound.
            if expected_peer is not None:
                persist_pin = True
            else:
                persist_pin = bool(
                    self._reconnect_book is not None
                    and self._reconnect_book.get_by_peer_id(their_peer_id)
                    is not None
                )
            ok, pinned = self.pins.check_and_pin(
                their_peer_id, their_ed25519, their_x25519,
                persist=persist_pin)
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

        Clears all logical sensitive state (stores, routing table, pins,
        ratchets, per-connection session/HMAC keys) as fast as possible and
        closes every connection. Does NOT stop the event loop; call stop()
        separately; the UIs terminate the process immediately afterwards,
        which is the real protection.

        NOTE: this is best-effort, not guaranteed zeroization. The long-lived
        identity private keys, the address-book/pin-store encryption keys, and
        any immutable `bytes`/`str` copies (ratchet keys, message plaintext)
        remain resident until the process exits; CPython cannot overwrite
        immutable objects in place. Rely on process termination for full
        clearance.
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

        # Wipe X3DH sessions + one-time prekey privates (issue #12).
        self._x3dh_send_sessions.clear()
        self._x3dh_recv_sessions.clear()
        self._opk_privs.clear()

        # Wipe message queue
        self._message_queue.clear()

        # Cancel all reconnect tasks
        for task in list(self._reconnect_tasks.values()):
            task.cancel()
        self._reconnect_tasks.clear()
        self._reconnect_book = None

        # Drop ratchet states and per-connection symmetric keys. These are the
        # session material we actually hold references to; null them before the
        # connections dict is cleared so they are not left dangling on live
        # connection objects.
        for conn in self._connections.values():
            if hasattr(conn, 'ratchet'):
                conn.ratchet = None
            if hasattr(conn, 'session_key'):
                conn.session_key = None
            if hasattr(conn, 'hmac_key'):
                conn.hmac_key = None

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
