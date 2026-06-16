"""Malphas — privacy-first P2P messenger."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("malphas")
except PackageNotFoundError:
    # Editable install before the package is registered, or running
    # straight from the source tree without a wheel install.
    __version__ = "0+unknown"

# Wire-protocol version. Bumped 1 -> 2 in `1.0.0-rc7`: the pre-1.0 audit
# made two intentional, breaking handshake/transport changes (the Ed25519
# handshake signature now covers the static X25519 key, and the Double
# Ratchet binds its cleartext header as AEAD AAD). The bump makes a
# version mismatch fail cleanly at the handshake instead of as a confusing
# signature error. See PROTOCOL.md for the full normative spec.
WIRE_VERSION = 2

__all__ = ["__version__", "WIRE_VERSION"]
