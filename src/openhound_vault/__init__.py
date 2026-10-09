"""OpenHound extension for HashiCorp Vault."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("openhound-vault")
except PackageNotFoundError:
    __version__ = "0.1.0"

__all__ = ["__version__"]

