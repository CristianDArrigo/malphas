"""Malphas — privacy-first P2P messenger."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("malphas")
except PackageNotFoundError:
    # Editable install before the package is registered, or running
    # straight from the source tree without a wheel install.
    __version__ = "0+unknown"

__all__ = ["__version__"]
