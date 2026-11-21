"""Hardened local SBOM backend supporting CycloneDX (1.4-1.6) and SPDX (2.2-2.3) JSON."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from zerobom.backends.base import BackendConfigError
from zerobom.backends.sbom_parser import (
    MAX_CYCLONEDX_DEPTH,
    MAX_SBOM_FILE_BYTES,
    InMemoryComponentIndex,
    SbomParseError,
    derive_sbom_asset,
    is_cyclonedx_document,
    is_spdx_document,
    parse_cyclonedx_dict,
    parse_spdx_dict,
)
from zerobom.models import InventoryComponent, PackageQuery

MAX_SBOM_FILES = 1000

__all__ = [
    "MAX_CYCLONEDX_DEPTH",
    "MAX_SBOM_FILES",
    "MAX_SBOM_FILE_BYTES",
    "LocalSbomBackend",
    "SbomParseError",
]


def _is_path_within_root(path: Path, root: Path) -> bool:
    """Return True if ``path`` resolves inside ``root`` (defends against symlink/traversal)."""
    try:
        return path.resolve().is_relative_to(root.resolve())
    except (OSError, ValueError):
        return False


def _load_sbom_json(file_path: Path, *, max_file_bytes: int) -> dict[str, Any]:
    """Read and parse a bounded UTF-8 JSON object from disk."""
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        raise SbomParseError(f"Failed to stat SBOM file {file_path}: {exc}") from exc

    if size > max_file_bytes:
        raise SbomParseError(
            f"SBOM file {file_path} exceeds maximum size of {max_file_bytes} bytes ({size} bytes)."
        )

    try:
        raw_text = file_path.read_text(encoding="utf-8")
        data = json.loads(raw_text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SbomParseError(f"Invalid JSON in SBOM file {file_path}: {exc}") from exc

    if not isinstance(data, dict):
        raise SbomParseError(f"SBOM root in {file_path} must be a JSON object.")

    return data


def _parse_positive_int_option(config: Mapping[str, Any], key: str, default: int) -> int:
    """Parse an integer option from CLI/file config safely, rejecting booleans and <= 0."""
    if key not in config or config[key] is None:
        return default
    raw = config[key]
    if isinstance(raw, bool):
        raise BackendConfigError(f"local_sbom option {key!r} must be a positive integer.")
    if isinstance(raw, int):
        parsed = raw
    elif isinstance(raw, str):
        try:
            parsed = int(raw.strip())
        except ValueError as exc:
            raise BackendConfigError(
                f"local_sbom option {key!r} must be a positive integer, got {raw!r}."
            ) from exc
    else:
        raise BackendConfigError(f"local_sbom option {key!r} must be a positive integer.")

    if parsed < 1:
        raise BackendConfigError(f"local_sbom option {key!r} must be >= 1.")
    return parsed


class LocalSbomBackend:
    """Zero-config inventory backend reading CycloneDX and SPDX JSON SBOMs from disk."""

    def __init__(
        self,
        paths: Path | str | Sequence[Path | str],
        *,
        max_file_bytes: int = MAX_SBOM_FILE_BYTES,
        max_files: int = MAX_SBOM_FILES,
        max_depth: int = MAX_CYCLONEDX_DEPTH,
    ) -> None:
        """Load and index CycloneDX and SPDX JSON SBOM files from files or directories.

        Args:
            paths: File path, directory path, or sequence of paths to scan.
            max_file_bytes: Maximum allowed byte size per SBOM JSON file.
            max_files: Maximum number of JSON files permitted in a directory scan.
            max_depth: Maximum CycloneDX nested ``components[]`` depth permitted.

        Raises:
            ValueError: If resource ceilings are non-positive or ``paths`` is empty.
            SbomParseError: If an explicit file is missing/malformed/oversized/unrecognized,
                a directory exceeds ``max_files``, or a nested SBOM exceeds ``max_depth``.
        """
        if max_file_bytes < 1 or max_files < 1 or max_depth < 1:
            raise ValueError("max_file_bytes, max_files, and max_depth must be >= 1")

        self._max_file_bytes = max_file_bytes
        self._max_files = max_files
        self._max_depth = max_depth

        path_items = [paths] if isinstance(paths, (Path, str)) else list(paths)
        if not path_items:
            raise ValueError("At least one SBOM file or directory path must be provided.")

        loaded_files: list[Path] = []
        skipped_files: list[Path] = []
        all_components: list[InventoryComponent] = []

        for raw_item in path_items:
            target = Path(raw_item)
            if not target.exists():
                raise SbomParseError(f"SBOM path does not exist: {target}")

            if target.is_file():
                data = _load_sbom_json(target, max_file_bytes=self._max_file_bytes)
                parsed = self._parse_explicit_file(target, data)
                loaded_files.append(target)
                all_components.extend(parsed)
            elif target.is_dir():
                self._scan_directory(
                    target,
                    loaded_files=loaded_files,
                    skipped_files=skipped_files,
                    all_components=all_components,
                )
            else:
                raise SbomParseError(f"Unsupported SBOM path type: {target}")

        self._loaded_files = tuple(loaded_files)
        self._skipped_files = tuple(skipped_files)
        self._index = InMemoryComponentIndex(all_components)

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> LocalSbomBackend:
        """Instantiate :class:`LocalSbomBackend` from parsed CLI or YAML/JSON configuration.

        Args:
            config: Mapping containing ``paths`` (or ``path`` / ``sbom``) plus optional
                ``max_file_bytes``, ``max_files``, and ``max_depth`` integer ceilings.

        Returns:
            Initialized :class:`LocalSbomBackend`.

        Raises:
            BackendConfigError: If ``paths`` is missing or configuration values are invalid.
        """
        raw_paths: Any = None
        for key in ("paths", "path", "sbom"):
            if key in config and config[key] is not None:
                raw_paths = config[key]
                break

        if raw_paths is None:
            raise BackendConfigError("local_sbom configuration requires 'paths' (or 'sbom').")

        if isinstance(raw_paths, (Path, str)):
            if isinstance(raw_paths, str) and not raw_paths.strip():
                raise BackendConfigError("local_sbom 'paths' must not be empty.")
            validated_paths: Path | str | Sequence[Path | str] = raw_paths
        elif isinstance(raw_paths, Sequence):
            items: list[Path | str] = []
            for item in raw_paths:
                if not isinstance(item, (Path, str)):
                    raise BackendConfigError("local_sbom 'paths' items must be file or dir paths.")
                if isinstance(item, str) and not item.strip():
                    raise BackendConfigError("local_sbom 'paths' must not contain empty paths.")
                items.append(item)
            if not items:
                raise BackendConfigError("local_sbom 'paths' must contain at least one path.")
            validated_paths = tuple(items)
        else:
            raise BackendConfigError("local_sbom 'paths' must be a path or sequence of paths.")

        max_file_bytes = _parse_positive_int_option(config, "max_file_bytes", MAX_SBOM_FILE_BYTES)
        max_files = _parse_positive_int_option(config, "max_files", MAX_SBOM_FILES)
        max_depth = _parse_positive_int_option(config, "max_depth", MAX_CYCLONEDX_DEPTH)
        return cls(
            validated_paths,
            max_file_bytes=max_file_bytes,
            max_files=max_files,
            max_depth=max_depth,
        )

    def _parse_document(
        self,
        file_path: Path,
        data: dict[str, Any],
    ) -> tuple[InventoryComponent, ...] | None:
        if not is_cyclonedx_document(data) and not is_spdx_document(data):
            return None
        asset = derive_sbom_asset(
            data,
            asset_id=str(file_path.resolve()),
            backend=self.name,
            location=str(file_path),
        )
        if is_cyclonedx_document(data):
            return parse_cyclonedx_dict(
                data,
                asset=asset,
                source_label=str(file_path),
                max_depth=self._max_depth,
            )
        return parse_spdx_dict(data, asset=asset)

    def _parse_explicit_file(
        self,
        file_path: Path,
        data: dict[str, Any],
    ) -> tuple[InventoryComponent, ...]:
        parsed = self._parse_document(file_path, data)
        if parsed is None:
            raise SbomParseError(
                f"Unrecognized SBOM schema in {file_path} (expected CycloneDX or SPDX 2.x JSON)."
            )
        return parsed

    def _scan_directory(
        self,
        root: Path,
        *,
        loaded_files: list[Path],
        skipped_files: list[Path],
        all_components: list[InventoryComponent],
    ) -> None:
        json_candidates = sorted(root.rglob("*.json"))
        if len(json_candidates) > self._max_files:
            raise SbomParseError(
                f"Directory {root} contains {len(json_candidates)} JSON files, "
                f"exceeding max_files={self._max_files}."
            )

        for candidate in json_candidates:
            # Skip symlinks or resolved paths escaping the scan root to block symlink traversal.
            if candidate.is_symlink() or not _is_path_within_root(candidate, root):
                skipped_files.append(candidate)
                continue
            if not candidate.is_file():
                continue

            data = _load_sbom_json(candidate, max_file_bytes=self._max_file_bytes)
            parsed = self._parse_document(candidate, data)
            if parsed is not None:
                loaded_files.append(candidate)
                all_components.extend(parsed)
            else:
                skipped_files.append(candidate)

    @property
    def name(self) -> str:
        """Backend identifier registered in ``zerobom.backends``."""
        return "local_sbom"

    @property
    def components(self) -> tuple[InventoryComponent, ...]:
        """All normalized inventory components parsed from configured SBOM files."""
        return self._index.components

    @property
    def loaded_files(self) -> tuple[Path, ...]:
        """SBOM files successfully parsed during initialization."""
        return self._loaded_files

    @property
    def skipped_files(self) -> tuple[Path, ...]:
        """JSON or symlinked files skipped during directory scanning."""
        return self._skipped_files

    def find_components(self, queries: Sequence[PackageQuery]) -> tuple[InventoryComponent, ...]:
        """Return candidate components matching any query in O(1) per index lookup.

        Args:
            queries: Canonical package descriptors built from an OSV advisory.

        Returns:
            Deduplicated tuple of matching :class:`InventoryComponent` objects.
        """
        return self._index.find_components(queries)
