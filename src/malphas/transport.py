"""
Transport layer abstraction.

DirectTransport: raw TCP, used for LAN or when at least one peer has a public IP.
TorTransport:    routes all connections through Tor SOCKS5 proxy and registers
                 a v3 hidden service so the node is reachable from anywhere,
                 behind any NAT, without exposing the real IP.

The .onion address is derived deterministically from the Ed25519 public key
using the same algorithm Tor uses for v3 hidden services. This means the
.onion address is stable across restarts as long as the passphrase is the same.

SOCKS5 client is implemented from scratch (asyncio, no external deps beyond stem).
stem is required only for TorTransport (hidden service registration).
"""

import asyncio
import base64
import hashlib
import struct
from typing import Optional, Tuple

# SOCKS5 constants
SOCKS5_VERSION = 0x05
SOCKS5_NO_AUTH = 0x00
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ATYP_DOMAINNAME = 0x03


# ── Onion address derivation ──────────────────────────────────────────────────

def ed25519_pub_to_onion(pub_bytes: bytes) -> str:
    """
    Derive a Tor v3 .onion address from an Ed25519 public key.
    Algorithm: https://spec.torproject.org/rend-spec-v3 section 6

    Format: base32(pubkey(32) + checksum(2) + version(1)) + ".onion"
    Checksum: SHA3-256(".onion checksum" + pubkey + version)[0:2]
    """
    version = bytes([3])
    checksum_input = b".onion checksum" + pub_bytes + version
    checksum = hashlib.sha3_256(checksum_input).digest()[:2]
    raw = pub_bytes + checksum + version
    return base64.b32encode(raw).decode().lower() + ".onion"


def onion_to_ed25519_pub(onion_address: str) -> bytes:
    """Extract Ed25519 public key from a v3 .onion address. Raises ValueError if invalid."""
    addr = onion_address.removesuffix(".onion").upper()
    try:
        raw = base64.b32decode(addr)
    except Exception as e:
        raise ValueError(f"Invalid onion address encoding: {e}") from e
    if len(raw) != 35:
        raise ValueError(f"Invalid onion address length: {len(raw)}")
    pub_bytes = raw[:32]
    checksum_stored = raw[32:34]
    version = raw[34:35]
    # Verify checksum
    checksum_input = b".onion checksum" + pub_bytes + version
    checksum_expected = hashlib.sha3_256(checksum_input).digest()[:2]
    if checksum_stored != checksum_expected:
        raise ValueError("Onion address checksum mismatch")
    return pub_bytes


# ── SOCKS5 async client ───────────────────────────────────────────────────────

async def socks5_connect(
    socks_host: str,
    socks_port: int,
    dest_host: str,
    dest_port: int,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """
    Open a SOCKS5 connection to dest_host:dest_port through a SOCKS5 proxy.
    Supports .onion addresses (ATYP_DOMAINNAME).
    Raises ConnectionError on failure.
    """
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(socks_host, socks_port),
        timeout=30.0,
    )

    try:
        # Step 1: auth negotiation — no auth
        writer.write(bytes([SOCKS5_VERSION, 1, SOCKS5_NO_AUTH]))
        await writer.drain()

        resp = await asyncio.wait_for(reader.readexactly(2), timeout=10.0)
        if resp[0] != SOCKS5_VERSION or resp[1] != SOCKS5_NO_AUTH:
            raise ConnectionError(f"SOCKS5 auth negotiation failed: {resp.hex()}")

        # Step 2: CONNECT request
        host_bytes = dest_host.encode()
        request = bytes([
            SOCKS5_VERSION,
            SOCKS5_CMD_CONNECT,
            0x00,                    # reserved
            SOCKS5_ATYP_DOMAINNAME,
            len(host_bytes),
        ]) + host_bytes + struct.pack(">H", dest_port)

        writer.write(request)
        await writer.drain()

        # Step 3: response
        header = await asyncio.wait_for(reader.readexactly(4), timeout=30.0)
        if header[0] != SOCKS5_VERSION:
            raise ConnectionError(f"SOCKS5 version mismatch in response: {header[0]}")
        if header[1] != 0x00:
            _SOCKS5_ERRORS = {
                0x01: "general failure",
                0x02: "connection not allowed",
                0x03: "network unreachable",
                0x04: "host unreachable",
                0x05: "connection refused",
                0x06: "TTL expired",
                0x07: "command not supported",
                0x08: "address type not supported",
            }
            reason = _SOCKS5_ERRORS.get(header[1], f"error code {header[1]}")
            raise ConnectionError(f"SOCKS5 connect failed: {reason}")

        # Read and discard the BND.ADDR / BND.PORT
        atyp = header[3]
        if atyp == 0x01:    # IPv4
            await reader.readexactly(4 + 2)
        elif atyp == 0x03:  # domain
            length = (await reader.readexactly(1))[0]
            await reader.readexactly(length + 2)
        elif atyp == 0x04:  # IPv6
            await reader.readexactly(16 + 2)

        return reader, writer

    except Exception:
        writer.close()
        raise


# ── Transport base ────────────────────────────────────────────────────────────

class BaseTransport:
    """Common interface for all transports."""

    async def connect(
        self, host: str, port: int
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        raise NotImplementedError

    async def start_server(
        self, host: str, port: int, client_handler
    ) -> asyncio.AbstractServer:
        raise NotImplementedError

    @property
    def public_address(self) -> Optional[str]:
        """The publicly reachable address for this node, or None if not known."""
        return None

    async def stop(self) -> None:
        pass


# ── Direct TCP transport ──────────────────────────────────────────────────────

class DirectTransport(BaseTransport):
    """Plain TCP. Works on LAN or when the node has a public IP."""

    def __init__(self, public_host: Optional[str] = None):
        self._public_host = public_host
        self._server: Optional[asyncio.AbstractServer] = None

    async def connect(self, host: str, port: int):
        return await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=10.0
        )

    async def start_server(self, host: str, port: int, client_handler):
        self._server = await asyncio.start_server(client_handler, host, port)
        return self._server

    @property
    def public_address(self) -> Optional[str]:
        return self._public_host

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()


# ── Tor transport ─────────────────────────────────────────────────────────────

class TorTransport(BaseTransport):
    """
    Routes all connections through Tor.
    - Outbound: SOCKS5 proxy (default 127.0.0.1:9050)
    - Inbound:  Tor v3 hidden service (registered via control port 9051)

    The .onion address is derived from the node's Ed25519 public key,
    making it stable and deterministic across restarts.

    Requires: Tor running on the host machine.
    Optional: stem installed for hidden service registration.
    """

    def __init__(
        self,
        socks_host: str = "127.0.0.1",
        socks_port: int = 9050,
        control_host: str = "127.0.0.1",
        control_port: int = 9051,
        control_password: Optional[str] = None,
    ):
        self._socks_host = socks_host
        self._socks_port = socks_port
        self._control_host = control_host
        self._control_port = control_port
        self._control_password = control_password
        self._onion_address: Optional[str] = None
        self._hidden_service = None
        self._controller = None
        self._server: Optional[asyncio.AbstractServer] = None

    async def start_hidden_service(
        self,
        ed25519_pub_bytes: bytes,
        ed25519_priv_bytes: bytes,
        local_port: int,
    ) -> str:
        """
        Register a Tor v3 hidden service using our Ed25519 keypair.
        Returns the .onion address.

        The hidden service listens on the Tor network and forwards
        connections to 127.0.0.1:local_port.
        """
        try:
            from stem.control import Controller
            from stem.descriptor.hidden_service import HiddenServiceDescriptor
        except ImportError:
            raise RuntimeError(
                "stem is required for Tor hidden service support.\n"
                "Install it with: pip install stem"
            )

        # Compute the .onion address from our pubkey
        onion = ed25519_pub_to_onion(ed25519_pub_bytes)

        # Format key for stem: base64(priv_seed(32) + pub(32))
        expanded = ed25519_priv_bytes + ed25519_pub_bytes
        key_content = base64.b64encode(expanded).decode()

        # Run all stem operations in a single executor call.
        # stem's Controller is not thread-safe — splitting across
        # multiple executor calls causes silent registration failures.
        def _register():
            ctrl = Controller.from_port(
                address=self._control_host,
                port=self._control_port,
            )
            ctrl.authenticate(password=self._control_password)
            hs = ctrl.create_ephemeral_hidden_service(
                {80: local_port},
                key_type="ED25519-V3",
                key_content=key_content,
                await_publication=False,
            )
            return ctrl, hs

        loop = asyncio.get_running_loop()
        controller, hs = await loop.run_in_executor(None, _register)

        self._controller = controller
        self._hidden_service = hs
        self._onion_address = onion
        return onion

    async def connect(self, host: str, port: int):
        """Connect to host:port through Tor SOCKS5. host can be a .onion address."""
        return await socks5_connect(
            self._socks_host, self._socks_port,
            host, port,
        )

    async def start_server(self, host: str, port: int, client_handler):
        """Start local TCP server that Tor forwards inbound connections to."""
        self._server = await asyncio.start_server(
            client_handler, "127.0.0.1", port
        )
        return self._server

    @property
    def public_address(self) -> Optional[str]:
        return self._onion_address

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        if self._hidden_service and self._controller:
            loop = asyncio.get_running_loop()
            try:
                hs_id = self._onion_address.removesuffix(".onion") if self._onion_address else None
                if hs_id:
                    await loop.run_in_executor(
                        None,
                        lambda: self._controller.remove_ephemeral_hidden_service(hs_id)
                    )
                await loop.run_in_executor(None, self._controller.close)
            except Exception:
                pass


# ── Tor availability check ────────────────────────────────────────────────────

async def tor_is_available(
    socks_host: str = "127.0.0.1",
    socks_port: int = 9050,
) -> bool:
    """
    Check if a Tor SOCKS5 proxy is available.
    Does not require stem — just tries a TCP connection.
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(socks_host, socks_port),
            timeout=2.0,
        )
        writer.close()
        return True
    except Exception:
        return False
