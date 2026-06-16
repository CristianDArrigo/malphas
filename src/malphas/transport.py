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
import logging
import struct

logger = logging.getLogger(__name__)

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
    # v3 onion addresses are version byte 0x03. Enforce it: the checksum
    # below is computed over the version, so an attacker could craft a
    # self-consistent address with a different version byte; rejecting
    # non-3 versions keeps this aligned with the v3 derivation spec.
    if version != b"\x03":
        raise ValueError(f"Unsupported onion version byte: {version!r}")
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
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
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
        else:
            # Unknown ATYP: we cannot know how many BND bytes follow, so the
            # stream is now unframable. Fail instead of returning a stream
            # with leftover proxy bytes that would corrupt the first read.
            raise ConnectionError(f"SOCKS5 unknown address type in reply: {atyp}")

        return reader, writer

    except Exception:
        writer.close()
        raise


# ── Transport base ────────────────────────────────────────────────────────────

class BaseTransport:
    """Common interface for all transports."""

    async def connect(
        self, host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        raise NotImplementedError

    async def start_server(
        self, host: str, port: int, client_handler
    ) -> asyncio.AbstractServer:
        raise NotImplementedError

    @property
    def public_address(self) -> str | None:
        """The publicly reachable address for this node, or None if not known."""
        return None

    async def stop(self) -> None:
        pass


# ── Direct TCP transport ──────────────────────────────────────────────────────

class DirectTransport(BaseTransport):
    """Plain TCP. Works on LAN or when the node has a public IP."""

    def __init__(self, public_host: str | None = None):
        self._public_host = public_host
        self._server: asyncio.AbstractServer | None = None

    async def connect(self, host: str, port: int):
        return await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=10.0
        )

    async def start_server(self, host: str, port: int, client_handler):
        self._server = await asyncio.start_server(client_handler, host, port)
        return self._server

    @property
    def public_address(self) -> str | None:
        return self._public_host

    async def stop(self):
        if self._server:
            self._server.close()
            # Bound the wait: wait_closed() blocks on in-flight connection
            # handlers, so a misbehaving/lingering peer must never be able
            # to stall shutdown indefinitely. Callers should close peer
            # connections before calling this.
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=5.0)
            except (asyncio.TimeoutError, Exception):
                pass


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
        control_password: str | None = None,
    ):
        self._socks_host = socks_host
        self._socks_port = socks_port
        self._control_host = control_host
        self._control_port = control_port
        self._control_password = control_password
        self._onion_address: str | None = None
        self._hs_dir = None
        self._hs_controller = None   # stem Controller holding the ephemeral HS
        self._server: asyncio.AbstractServer | None = None

    async def start_hidden_service(
        self,
        ed25519_pub_bytes: bytes,
        ed25519_priv_bytes: bytes,
        local_port: int,
        hs_dir: str | None = None,
    ) -> str:
        """
        Register a Tor v3 hidden service via the ControlPort (ADD_ONION).
        Returns the .onion address.

        No sudo, no filesystem, no `tor` restart: we hand Tor our own Ed25519
        key over the (cookie-authenticated) control port, so the onion is the
        same deterministic address every launch. The service is ephemeral —
        tied to this control connection and removed (DEL_ONION) automatically
        when the node stops or the process dies.

        Requires Tor's ControlPort enabled and authenticable (cookie auth: the
        user must be able to read the control auth cookie — typically by being
        in the `debian-tor`/`tor` group — or a control password). `hs_dir` is
        accepted for signature compatibility and ignored.
        """
        import base64
        import hashlib

        try:
            from stem.control import Controller
        except ImportError as e:
            raise RuntimeError(
                "stem is required for Tor hidden service support.\n"
                "Install it with: pip install stem"
            ) from e

        onion = ed25519_pub_to_onion(ed25519_pub_bytes)

        # Tor's ADD_ONION wants the *expanded* Ed25519 secret key — the clamp
        # of SHA-512(seed), 64 bytes — base64-encoded, NOT the 32-byte seed.
        h = hashlib.sha512(ed25519_priv_bytes).digest()
        expanded = bytearray(h)
        expanded[0] &= 248
        expanded[31] &= 127
        expanded[31] |= 64
        key_b64 = base64.b64encode(bytes(expanded)).decode()

        loop = asyncio.get_running_loop()

        def _add() -> None:
            controller = Controller.from_port(
                address=self._control_host, port=self._control_port)
            try:
                if self._control_password is not None:
                    controller.authenticate(password=self._control_password)
                else:
                    controller.authenticate()
            except Exception as e:
                controller.close()
                raise RuntimeError(
                    "Tor ControlPort authentication failed on "
                    f"{self._control_host}:{self._control_port} ({e}). Enable "
                    "`ControlPort 9051` + `CookieAuthentication 1` in torrc and "
                    "make sure your user can read the control auth cookie (add "
                    "it to the `debian-tor`/`tor` group), or set a control "
                    "password."
                ) from e
            try:
                # Ephemeral v3 HS from our own key. detached=False ties it to
                # this control connection: it lives exactly as long as we hold
                # the controller (closed in stop()) and is gone if we crash —
                # no stale registration, no key files, no torrc edits, no sudo.
                controller.create_ephemeral_hidden_service(
                    {80: f"127.0.0.1:{local_port}"},
                    key_type="ED25519-V3",
                    key_content=key_b64,
                    await_publication=False,
                    detached=False,
                )
            except Exception as e:
                controller.close()
                # "Onion address collision" = this onion is already registered
                # with Tor: by a persistent (torrc) hidden service for the same
                # identity, or another running instance. It's already serving
                # the same deterministic address (mapped to our local port), so
                # the node IS reachable — treat it as up and advertise the
                # onion. We don't own that service, so we keep no controller
                # for it (nothing to DEL_ONION on stop).
                if "collision" in str(e).lower():
                    return
                raise
            # Fresh ephemeral HS — hold the controller open so it lives exactly
            # as long as this connection (closed in stop()). Set here, inside
            # the worker, so a failure above leaves _hs_controller None.
            self._hs_controller = controller

        await loop.run_in_executor(None, _add)
        self._onion_address = onion
        self._hs_dir = hs_dir

        # Let Tor start publishing the descriptor before the onion goes out in
        # invites. Full publication can take ~30 s; we don't block startup on
        # it (a freshly shared invite is dialed by a human well after that).
        await asyncio.sleep(2)

        logger.debug(
            "hidden service via ADD_ONION: %s -> 127.0.0.1:%d",
            onion, local_port)
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
    def public_address(self) -> str | None:
        return self._onion_address

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=5.0)
            except (asyncio.TimeoutError, Exception):
                pass
        # Close the control connection holding the ephemeral hidden service:
        # Tor drops the onion (DEL_ONION) when its owning connection goes away.
        if self._hs_controller is not None:
            try:
                self._hs_controller.close()
            except Exception:  # noqa: S110
                pass
            self._hs_controller = None


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
