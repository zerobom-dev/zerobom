"""Cloud-agnostic inventory backend protocol and shared advisory matching helper."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from zerobom.models import InventoryComponent, MatchResult, OsvAdvisory, PackageQuery
from zerobom.verify.osv_compiler import build_package_queries, evaluate_inventory_component


class BackendError(RuntimeError):
    """Base exception for inventory backend loading, configuration, and query errors."""


class BackendLoadError(BackendError):
    """Raised when a requested inventory backend cannot be found, loaded, or instantiated."""


class BackendConfigError(BackendLoadError):
    """Raised when backend configuration options or credentials are invalid or missing."""


class BackendQueryError(BackendError):
    """Raised when an inventory backend runtime query fails or exceeds safety ceilings."""


@runtime_checkable
class InventoryBackend(Protocol):
    """Query-driven contract implemented by local SBOMs and external/cloud plugins.

    All backends return normalized :class:`InventoryComponent` entries; deterministic version
    range matching remains exclusively in :mod:`zerobom.verify.osv_compiler`.
    """

    @property
    def name(self) -> str:
        """Unique identifier for this inventory backend (e.g., ``"local_sbom"``)."""

    def find_components(self, queries: Sequence[PackageQuery]) -> tuple[InventoryComponent, ...]:
        """Look up candidate components matching any of the supplied package queries.

        Args:
            queries: Canonical package descriptors extracted from an OSV advisory.

        Returns:
            Tuple of matching :class:`InventoryComponent` records with attached ``AssetRef``.
        """


def match_advisory_with_backend(
    advisory: OsvAdvisory,
    backend: InventoryBackend,
    *,
    only_vulnerable: bool = True,
) -> tuple[MatchResult, ...]:
    """Query an :class:`InventoryBackend` and evaluate hits deterministically with ``univers``.

    Args:
        advisory: Compiled OSV advisory containing affected package definitions.
        backend: Any local or plugin-supplied :class:`InventoryBackend` implementation.
        only_vulnerable: When ``True``, filter out patched/non-vulnerable components.

    Returns:
        Deduplicated tuple of deterministic :class:`MatchResult` records.
    """
    queries = build_package_queries(advisory)
    if not queries:
        return ()

    candidates = backend.find_components(queries)
    results: list[MatchResult] = []
    seen: set[tuple[str, str, str, str, str]] = set()

    for component in candidates:
        match = evaluate_inventory_component(advisory, component)
        if match is None:
            continue
        if only_vulnerable and not match.is_vulnerable:
            continue
        dedup_key = (
            match.advisory_id,
            component.asset.asset_id,
            match.matched_purl,
            match.component_purl,
            match.installed_version,
        )
        if dedup_key not in seen:
            seen.add(dedup_key)
            results.append(match)

    return tuple(results)
