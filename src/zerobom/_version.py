"""Shared package version and repository metadata constants for ``zerobom``."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__: str = version("zerobom")
except PackageNotFoundError:  # pragma: no cover - uninstalled source fallback
    __version__ = "0.1.1"

REPOSITORY_URL: str = "https://github.com/zerobom-dev/zerobom"
HOMEPAGE_URL: str = "https://zerobom.dev/"
DEFAULT_USER_AGENT: str = f"zerobom/{__version__} (+{REPOSITORY_URL})"
