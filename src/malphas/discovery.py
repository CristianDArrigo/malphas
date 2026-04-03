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
from typing import Dict, List, Optional, Tuple


log = logging.getLogger("malphas.discovery")
log.addHandler(logging.NullHandler())  # no-log policy: NullHandler by default

K = 8  # Kademlia bucket size
ID_BITS = 160  # SHA1 = 160 bits


@dataclass
class PeerInfo:
    peer_id: str          # 40-char hex SHA1
    host: str
    port: int
    x25519_pub: bytes     # 32-byte X25519 public key
    ed25519_pub: bytes    # 32-byte Ed25519 public key
    last_seen: float = field(default_factory=time.time)

    def is_stale(self, timeout: float = 300.0) -> bool:
        return (time.time() - self.last_seen) > timeout

    def to_dict(self) -> dict:
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
        self._buckets: Dict[int, List[PeerInfo]] = {}
        self._by_id: Dict[str, PeerInfo] = {}

    def add(self, peer: PeerInfo) -> None:
        if peer.peer_id == self._my_id:
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

    def get(self, peer_id: str) -> Optional[PeerInfo]:
        return self._by_id.get(peer_id)

    def closest(self, target_id: str, k: int = K) -> List[PeerInfo]:
        """Return up to k peers closest to target_id."""
        all_peers = list(self._by_id.values())
        all_peers.sort(key=lambda p: xor_distance(p.peer_id, target_id))
        return all_peers[:k]

    def all_peers(self) -> List[PeerInfo]:
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
        self._mdns_task: Optional[asyncio.Task] = None

    def add_peer(
        self,
        peer_id: str,
        host: str,
        port: int,
        x25519_pub: bytes,
        ed25519_pub: bytes,
    ) -> PeerInfo:
        peer = PeerInfo(
            peer_id=peer_id,
            host=host,
            port=port,
            x25519_pub=x25519_pub,
            ed25519_pub=ed25519_pub,
        )
        self.table.add(peer)
        return peer

    def get_peer(self, peer_id: str) -> Optional[PeerInfo]:
        return self.table.get(peer_id)

    def all_peers(self) -> List[dict]:
        return [p.to_dict() for p in self.table.all_peers()]

    def select_relay_circuit(
        self,
        dest_id: str,
        hops: int = 3,
    ) -> List[Tuple[bytes, str]]:
        """
        Select a circuit of (x25519_pub, peer_id) tuples.
        Excludes self and destination from relays.
        Degrades gracefully: fewer hops if not enough peers.
        Returns: [(x25519_pub, peer_id), ...] ending with destination.
        """
        dest = self.table.get(dest_id)
        if dest is None:
            raise ValueError(f"Destination peer {dest_id} not in routing table")

        candidates = [
            p for p in self.table.all_peers()
            if p.peer_id != self._my_id and p.peer_id != dest_id
        ]

        # Select up to hops-1 relays
        import random
        relays = random.sample(candidates, min(hops - 1, len(candidates)))

        circuit = [(r.x25519_pub, r.peer_id) for r in relays]
        circuit.append((dest.x25519_pub, dest.peer_id))
        return circuit

    async def start_mdns(self, service_name: str, port: int) -> None:
        """Attempt mDNS registration. Silently skips if zeroconf unavailable."""
        try:
            from zeroconf.asyncio import AsyncZeroconf
            from zeroconf import ServiceInfo
            import socket

            info = ServiceInfo(
                "_malphas._tcp.local.",
                f"{service_name}._malphas._tcp.local.",
                addresses=[socket.inet_aton("127.0.0.1")],
                port=port,
                properties={"peer_id": self._my_id},
            )
            zc = AsyncZeroconf()
            await zc.async_register_service(info)
            self._mdns_task = asyncio.current_task()
        except ImportError:
            pass
        except Exception:
            pass

    def wipe(self) -> None:
        """Clear all peer data from memory."""
        self.table._by_id.clear()
        self.table._buckets.clear()
