"""Malphas — privacy-first P2P messenger."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("malphas")
except PackageNotFoundError:
    # Editable install before the package is registered, or running
    # straight from the source tree without a wheel install.
    __version__ = "0+unknown"

# Wire-protocol version. Frozen at 1 from `1.0.0-rc1`; see
# PROTOCOL.md for the full normative spec. Imported here so external
# tooling can sanity-check compatibility without pulling node.py.
WIRE_VERSION = 1

__all__ = ["__version__", "WIRE_VERSION"]
