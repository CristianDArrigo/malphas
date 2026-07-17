"""
Peer discovery.
- In-memory routing table (Kademlia-inspired XOR distance)
- mDNS for LAN auto-discovery
- Manual peer addition (no persistence)
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("malphas.discovery")
log.addHandler(logging.NullHandler())  # no-log policy: NullHandler by default

K = 8  # Kademlia bucket size
ID_BITS = 160  # BLAKE2s digest_size=20 → 160 bits (was SHA1 pre-0.5.0)


@dataclass
class PeerInfo:
    peer_id: str          # 40-char hex BLAKE2s(ed25519_pub, digest_size=20)
    host: str
    port: int
    x25519_pub: bytes     # 32-byte X25519 public key
    ed25519_pub: bytes    # 32-byte Ed25519 public key
    last_seen: float = field(default_factory=time.time)
    # Peer's signed prekey (X25519 pub), if known (from an invite). Enables
    # forward-secret X3DH delivery when we are not directly connected. None for
    # peers learned only via the authenticated handshake.
    spk_pub: bytes | None = None

    def is_stale(self, timeout: float = 300.0) -> bool:
        return (time.time() - self.last_seen) > timeout

    def to_dict(self) -> dict[str, Any]:
        return {
            "peer_id": self.peer_id,
            "host": self.host,
            "port": self.port,
            "x25519_pub": self.x25519_pub.hex(),
            "ed25519_pub": self.ed25519_pub.hex(),
            "last_seen": self.last_seen,
        }


def xor_distance(a: str, b: str) -> int:
    """XOR distance between two hex peer IDs."""
    return int(a, 16) ^ int(b, 16)


def bucket_index(my_id: str, peer_id: str) -> int:
    """Kademlia bucket index based on XOR distance."""
    dist = xor_distance(my_id, peer_id)
    if dist == 0:
        return 0
    return dist.bit_length() - 1


class RoutingTable:
    """
    Simplified Kademlia routing table.
    No disk persistence. Wiped on shutdown.
    """

    def __init__(self, my_id: str):
        self._my_id = my_id
        self._buckets: dict[int, list[PeerInfo]] = {}
        self._by_id: dict[str, PeerInfo] = {}

    def add(self, peer: PeerInfo) -> None:
        if peer.peer_id == self._my_id:
            return
        # peer_id must be a 40-char hex string. Anything else (e.g. a
        # malformed value off an untrusted gossip/announce path) would make
        # xor_distance's int(peer_id, 16) raise, or an over-long value would
        # blow the bucket index past the 0..159 model. Reject silently.
        pid = peer.peer_id
        if len(pid) != 40 or not all(c in "0123456789abcdef" for c in pid):
            return
        idx = bucket_index(self._my_id, peer.peer_id)
        if idx not in self._buckets:
            self._buckets[idx] = []
        bucket = self._buckets[idx]

        # Update if known
        if peer.peer_id in self._by_id:
            existing = self._by_id[peer.peer_id]
            existing.host = peer.host
            existing.port = peer.port
            existing.x25519_pub = peer.x25519_pub
            existing.ed25519_pub = peer.ed25519_pub
            # Keep a known signed prekey if this update doesn't carry one (the
            # handshake path has no SPK; don't clobber one learned via invite).
            if peer.spk_pub is not None:
                existing.spk_pub = peer.spk_pub
            existing.last_seen = time.time()
            return

        # Add new peer
        if len(bucket) < K:
            bucket.append(peer)
            self._by_id[peer.peer_id] = peer
        else:
            # Evict stalest if stale, otherwise drop (simplified)
            stale = [p for p in bucket if p.is_stale()]
            if stale:
                oldest = max(stale, key=lambda p: time.time() - p.last_seen)
                bucket.remove(oldest)
                del self._by_id[oldest.peer_id]
                bucket.append(peer)
                self._by_id[peer.peer_id] = peer

    def get(self, peer_id: str) -> PeerInfo | None:
        return self._by_id.get(peer_id)

    def closest(self, target_id: str, k: int = K) -> list[PeerInfo]:
        """Return up to k peers closest to target_id."""
        all_peers = list(self._by_id.values())
        all_peers.sort(key=lambda p: xor_distance(p.peer_id, target_id))
        return all_peers[:k]

    def all_peers(self) -> list[PeerInfo]:
        return list(self._by_id.values())

    def remove(self, peer_id: str) -> None:
        if peer_id not in self._by_id:
            return
        peer = self._by_id.pop(peer_id)
        idx = bucket_index(self._my_id, peer_id)
        if idx in self._buckets:
            self._buckets[idx] = [p for p in self._buckets[idx] if p.peer_id != peer_id]

    def purge_stale(self, timeout: float = 300.0) -> int:
        stale = [p for p in self._by_id.values() if p.is_stale(timeout)]
        for p in stale:
            self.remove(p.peer_id)
        return len(stale)

    def size(self) -> int:
        return len(self._by_id)


class PeerDiscovery:
    """
    Combines routing table with manual peer registration.
    mDNS support is optional (requires zeroconf).
    """

    def __init__(self, my_id: str):
        self.table = RoutingTable(my_id)
        self._my_id = my_id
        self._mdns_task: asyncio.Task[None] | None = None
        self._zc: Any = None          # AsyncZeroconf handle (kept so we can close it)
        self._mdns_info: Any = None   # registered ServiceInfo (for unregister)

    def add_peer(
        self,
        peer_id: str,
        host: str,
        port: int,
        x25519_pub: bytes,
        ed25519_pub: bytes,
        spk_pub: bytes | None = None,
    ) -> PeerInfo:
        peer = PeerInfo(
            peer_id=peer_id,
            host=host,
            port=port,
            x25519_pub=x25519_pub,
            ed25519_pub=ed25519_pub,
            spk_pub=spk_pub,
        )
        self.table.add(peer)
        # RoutingTable.add stores its own PeerInfo object (or updates an
        # existing one); return the authoritative stored instance so callers
        # see merged fields (e.g. a preserved SPK).
        return self.table.get(peer_id) or peer

    def get_peer(self, peer_id: str) -> PeerInfo | None:
        return self.table.get(peer_id)

    def all_peers(self) -> list[dict[str, Any]]:
        return [p.to_dict() for p in self.table.all_peers()]

    def select_relay_circuit(
        self,
        dest_id: str,
        hops: int = 3,
        relay_pool: set[str] | None = None,
    ) -> list[tuple[bytes, str]]:
        """
        Select a circuit of (x25519_pub, peer_id) tuples.
        Excludes self and destination from relays.
        Degrades gracefully: fewer hops if not enough peers.
        Returns: [(x25519_pub, peer_id), ...] ending with destination.

        Uses secrets.SystemRandom (cryptographically strong, OS entropy)
        rather than the default Mersenne-Twister-based random module.
        Predictable circuits would let an attacker bias which relay sees
        which message.
        """
        dest = self.table.get(dest_id)
        if dest is None:
            raise ValueError(f"Destination peer {dest_id} not in routing table")

        candidates = [
            p for p in self.table.all_peers()
            if p.peer_id != self._my_id and p.peer_id != dest_id
        ]

        # Only relay through peers we actually have a live connection to.
        # The first hop of the circuit is sent over an EXISTING connection
        # (node looks it up in self._connections); a relay we aren't
        # connected to as first hop means the send silently fails and the
        # message is dropped. When `relay_pool` is given (the set of
        # connected, authenticated peer_ids), filter candidates to it — so
        # with no usable relays the circuit degrades to a direct hop to the
        # destination, which is the common 1:1 case.
        if relay_pool is not None:
            candidates = [p for p in candidates if p.peer_id in relay_pool]

        import secrets as _secrets
        rng = _secrets.SystemRandom()
        relays = rng.sample(candidates, min(hops - 1, len(candidates)))

        circuit = [(r.x25519_pub, r.peer_id) for r in relays]
        circuit.append((dest.x25519_pub, dest.peer_id))
        return circuit

    async def start_mdns(self, service_name: str, port: int) -> None:
        """Attempt mDNS registration. Silently skips if zeroconf unavailable."""
        try:
            import socket

            from zeroconf import ServiceInfo
            from zeroconf.asyncio import AsyncZeroconf

            # NOTE: deliberately do NOT advertise the stable peer_id as an
            # mDNS property. Broadcasting it leaks a persistent identifier to
            # every device on the LAN, undercutting the project's anonymity
            # goals — and nothing in malphas reads it (identity is
            # established by the authenticated handshake after connect).
            info = ServiceInfo(
                "_malphas._tcp.local.",
                f"{service_name}._malphas._tcp.local.",
                addresses=[socket.inet_aton("127.0.0.1")],
                port=port,
                properties={},
            )
            zc = AsyncZeroconf()
            await zc.async_register_service(info)
            # Keep references so the service can actually be unregistered and
            # the socket closed on shutdown. The previous code stored
            # asyncio.current_task() (which had already finished), letting `zc`
            # get garbage-collected and leaving the registration dangling.
            self._zc = zc
            self._mdns_info = info
        except ImportError:
            pass
        except Exception:
            pass

    async def stop_mdns(self) -> None:
        """Unregister the mDNS service and close the zeroconf socket."""
        zc = self._zc
        if zc is None:
            return
        try:
            if self._mdns_info is not None:
                await zc.async_unregister_service(self._mdns_info)
            await zc.async_close()
        except Exception:
            pass
        finally:
            self._zc = None
            self._mdns_info = None

    def wipe(self) -> None:
        """Clear all peer data from memory."""
        self.table._by_id.clear()
        self.table._buckets.clear()
