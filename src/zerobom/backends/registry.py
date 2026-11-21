"""Entry-point plugin loader, config parser, and registry for ``zerobom.backends``."""

from __future__ import annotations

import importlib.metadata
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from zerobom.backends.base import (
    BackendConfigError,
    BackendLoadError,
    InventoryBackend,
)
from zerobom.backends.local_sbom import LocalSbomBackend

BACKEND_ENTRY_POINT_GROUP = "zerobom.backends"
MAX_BACKEND_CONFIG_BYTES = 1 * 1024 * 1024
_BACKEND_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_CONFIG_KEY_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_-]{0,63}$")


def _has_control_chars(value: str) -> bool:
    """Return True if ``value`` contains ASCII control characters (including CRLF or NUL)."""
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _default_entry_points(group: str) -> Iterable[Any]:
    """Discover installed Python entry points for the requested group."""
    return importlib.metadata.entry_points(group=group)


def parse_backend_options(
    raw_options: Sequence[str] = (),
    *,
    config_path: Path | None = None,
    max_config_bytes: int = MAX_BACKEND_CONFIG_BYTES,
) -> dict[str, Any]:
    """Parse backend plugin configuration from an optional YAML/JSON file and CLI flags.

    CLI ``KEY=VALUE`` options override keys loaded from ``config_path``. Repeated CLI keys
    are collected into a list of strings so plugins accepting sequences (such as multiple SBOM
    paths or namespaces) receive all supplied values cleanly.

    Args:
        raw_options: Sequence of ``KEY=VALUE`` strings supplied on the CLI.
        config_path: Optional path to a YAML or JSON backend config file.
        max_config_bytes: Maximum allowed config file byte size.

    Returns:
        Validated dictionary ready for :meth:`BackendRegistry.create` ``config=...``.

    Raises:
        BackendConfigError: If the config file is missing/oversized/malformed, contains
            invalid keys, or any CLI ``KEY=VALUE`` option is malformed or contains control chars.
    """
    if max_config_bytes < 1:
        raise ValueError("max_config_bytes must be >= 1")

    merged: dict[str, Any] = {}
    if config_path is not None:
        if not config_path.exists() or not config_path.is_file():
            raise BackendConfigError(f"Backend config file does not exist: {config_path}")
        try:
            size = config_path.stat().st_size
        except OSError as exc:
            raise BackendConfigError(f"Failed to stat backend config {config_path}: {exc}") from exc
        if size > max_config_bytes:
            raise BackendConfigError(
                f"Backend config {config_path} exceeds max size of {max_config_bytes} bytes."
            )
        try:
            raw_text = config_path.read_text(encoding="utf-8")
            parsed_yaml = yaml.safe_load(raw_text)
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            raise BackendConfigError(
                f"Invalid YAML/JSON in backend config {config_path}: {exc}"
            ) from exc

        if parsed_yaml is None:
            parsed_yaml = {}
        if not isinstance(parsed_yaml, dict):
            raise BackendConfigError(
                f"Backend config {config_path} root must be a YAML/JSON mapping."
            )

        if "options" in parsed_yaml:
            raw_section = parsed_yaml["options"]
            if not isinstance(raw_section, dict):
                raise BackendConfigError(
                    f"Backend config {config_path} 'options' section must be a mapping."
                )
            section: Mapping[Any, Any] = raw_section
        else:
            section = parsed_yaml

        for raw_key, raw_val in section.items():
            if not isinstance(raw_key, str):
                raise BackendConfigError("Backend config keys must be strings.")
            if _has_control_chars(raw_key):
                raise BackendConfigError(
                    f"Invalid backend config key {raw_key!r}; keys must not contain "
                    "control characters."
                )
            key = raw_key.strip()
            if not _CONFIG_KEY_RE.match(key):
                raise BackendConfigError(
                    f"Invalid backend config key {raw_key!r}; expected identifier "
                    "matching ^[a-zA-Z_][a-zA-Z0-9_-]{0,63}$."
                )
            merged[key] = raw_val

    cli_values: dict[str, list[str]] = {}
    for entry in raw_options:
        if "=" not in entry:
            raise BackendConfigError(
                f"Invalid backend option {entry!r}; expected KEY=VALUE format."
            )
        raw_key, raw_val = entry.split("=", 1)
        if _has_control_chars(raw_key) or _has_control_chars(raw_val):
            raise BackendConfigError(
                f"Invalid backend option {entry!r}; options must not contain control characters."
            )
        key = raw_key.strip()
        if not _CONFIG_KEY_RE.match(key):
            raise BackendConfigError(
                f"Invalid backend option {entry!r}; keys must match "
                "^[a-zA-Z_][a-zA-Z0-9_-]{0,63}$ and contain no control characters."
            )
        cli_values.setdefault(key, []).append(raw_val)

    for key, values in cli_values.items():
        merged[key] = values if len(values) > 1 else values[0]

    return merged


class BackendRegistry:
    """Discovers, validates, and instantiates built-in and plugin inventory backends."""

    def __init__(
        self,
        *,
        entry_points_provider: Callable[[str], Iterable[Any]] | None = None,
        include_builtins: bool = True,
    ) -> None:
        """Initialize the backend registry.

        Args:
            entry_points_provider: Optional callable overriding ``importlib.metadata.entry_points``
                for isolated offline testing of third-party plugins.
            include_builtins: Whether to register the built-in ``local_sbom`` backend automatically.
        """
        self._entry_points_provider = entry_points_provider or _default_entry_points
        self._factories: dict[str, Callable[..., Any]] = {}
        if include_builtins:
            self._factories["local_sbom"] = LocalSbomBackend

    def register(self, name: str, factory: Callable[..., InventoryBackend]) -> None:
        """Manually register an inventory backend factory under a validated name.

        Args:
            name: Backend identifier matching ``^[a-z][a-z0-9_-]{0,63}$``.
            factory: Callable returning an :class:`InventoryBackend` instance.

        Raises:
            ValueError: If ``name`` is invalid or ``factory`` is not callable.
        """
        if not _BACKEND_NAME_RE.match(name):
            raise ValueError(
                f"Invalid backend name {name!r}; expected lowercase identifier "
                "matching ^[a-z][a-z0-9_-]{0,63}$"
            )
        if not callable(factory):
            raise ValueError("Backend factory must be callable")
        self._factories[name] = factory

    def _discover_entry_points(self) -> dict[str, Any]:
        """Collect valid entry points for ``zerobom.backends`` without importing targets."""
        discovered: dict[str, Any] = {}
        for ep in self._entry_points_provider(BACKEND_ENTRY_POINT_GROUP):
            ep_name = getattr(ep, "name", None)
            if isinstance(ep_name, str) and _BACKEND_NAME_RE.match(ep_name):
                discovered[ep_name] = ep
        return discovered

    def list_backends(self) -> tuple[str, ...]:
        """Return sorted valid names of all registered and entry-point-discovered backends."""
        names = set(self._factories.keys()) | set(self._discover_entry_points().keys())
        return tuple(sorted(names))

    def get_factory(self, name: str) -> Callable[..., Any]:
        """Resolve and lazily load the factory callable for a named backend.

        Args:
            name: Registered or entry-point backend identifier.

        Returns:
            Factory callable capable of instantiating the backend.

        Raises:
            BackendLoadError: If ``name`` is invalid, missing, fails to import, or is not callable.
        """
        if not _BACKEND_NAME_RE.match(name):
            raise BackendLoadError(f"Invalid backend name {name!r}.")

        if name in self._factories:
            return self._factories[name]

        discovered = self._discover_entry_points()
        ep = discovered.get(name)
        if ep is None:
            available = ", ".join(self.list_backends()) or "none"
            raise BackendLoadError(
                f"Unknown inventory backend {name!r}. Available backends: {available}."
            )

        try:
            loaded = ep.load()
        except Exception as exc:
            raise BackendLoadError(
                f"Failed to load entry point for backend {name!r}: {exc}"
            ) from exc

        if not callable(loaded):
            raise BackendLoadError(
                f"Entry point for backend {name!r} resolved to non-callable {loaded!r}."
            )

        factory = cast(Callable[..., Any], loaded)
        self._factories[name] = factory
        return factory

    def create(
        self,
        name: str,
        *,
        config: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> InventoryBackend:
        """Instantiate and protocol-verify a named inventory backend.

        When ``config`` is supplied and the backend factory defines a callable ``from_config``
        hook, ``from_config(merged_config)`` is invoked; otherwise keyword arguments are passed
        directly to the backend constructor.

        Args:
            name: Registered or plugin backend name.
            config: Optional parsed configuration mapping (from :func:`parse_backend_options`).
            **kwargs: Explicit keyword arguments forwarded or merged into ``config``.

        Returns:
            Instantiated object satisfying :class:`InventoryBackend`.

        Raises:
            BackendLoadError: If loading/instantiation fails or the object does not implement
                :class:`InventoryBackend`.
            BackendConfigError: Propagated directly if configuration validation fails.
        """
        factory = self.get_factory(name)
        try:
            if config is not None:
                merged = {**config, **kwargs}
                from_config_hook = getattr(factory, "from_config", None)
                if callable(from_config_hook):
                    instance = from_config_hook(merged)
                else:
                    instance = factory(**merged)
            else:
                instance = factory(**kwargs)
        except BackendLoadError:
            raise
        except Exception as exc:
            raise BackendLoadError(f"Failed to instantiate backend {name!r}: {exc}") from exc

        if not isinstance(instance, InventoryBackend):
            raise BackendLoadError(
                f"Backend {name!r} instance {instance!r} does not satisfy InventoryBackend."
            )
        return instance
