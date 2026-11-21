"""Reusable protocol and contract conformance harness for ``zerobom.backends`` plugins."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from zerobom.backends.base import InventoryBackend, match_advisory_with_backend
from zerobom.models import (
    InventoryComponent,
    MatchResult,
    OsvAdvisory,
    OsvAffected,
    OsvPackage,
    OsvRange,
    OsvRangeEvent,
)
from zerobom.verify.osv_compiler import build_package_queries

_CONFORMANCE_BACKEND_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_CONFORMANCE_TS = datetime(2026, 5, 1, 0, 0, 0, tzinfo=UTC)


class BackendConformanceError(AssertionError):
    """Raised when an :class:`InventoryBackend` plugin violates conformance invariants."""


@dataclass(frozen=True)
class BackendConformanceCase:
    """Parameterized conformance test suite describing expected plugin matching behavior.

    Attributes:
        expected_backend_name: Expected value of ``backend.name``.
        vulnerable_advisory: Advisory that must match at least ``min_vulnerable_hits`` components.
        safe_advisory: Same package with a fixed bound lower than installed versions (0 hits).
        unmatched_advisory: Unrelated non-existent package (must return 0 hits).
        min_vulnerable_hits: Minimum vulnerable matches expected for ``vulnerable_advisory``.
    """

    expected_backend_name: str
    vulnerable_advisory: OsvAdvisory
    safe_advisory: OsvAdvisory
    unmatched_advisory: OsvAdvisory
    min_vulnerable_hits: int = 1


def build_default_conformance_case(
    *,
    backend_name: str,
    package_name: str = "requests",
    ecosystem: str = "PyPI",
    canonical_purl: str = "pkg:pypi/requests",
    vulnerable_fixed: str = "2.31.0",
    safe_fixed: str = "1.0.0",
) -> BackendConformanceCase:
    """Construct a standard three-advisory conformance fixture for a backend plugin.

    Args:
        backend_name: Expected plugin ``name`` property.
        package_name: Target package present in the plugin's inventory.
        ecosystem: OSV ecosystem string for ``package_name``.
        canonical_purl: Versionless canonical PURL matching the inventory entry.
        vulnerable_fixed: Version higher than installed version (triggers vulnerable hit).
        safe_fixed: Version lower than installed version (must yield zero vulnerable hits).

    Returns:
        Configured :class:`BackendConformanceCase`.
    """
    vulnerable_advisory = OsvAdvisory(
        id="PRECVE-2026-00000001",
        modified=_CONFORMANCE_TS,
        published=_CONFORMANCE_TS,
        summary=f"Conformance vulnerable advisory for {package_name}",
        affected=(
            OsvAffected(
                package=OsvPackage(ecosystem=ecosystem, name=package_name, purl=canonical_purl),
                ranges=(
                    OsvRange(
                        type="ECOSYSTEM",
                        events=(
                            OsvRangeEvent(introduced="0"),
                            OsvRangeEvent(fixed=vulnerable_fixed),
                        ),
                    ),
                ),
            ),
        ),
    )
    safe_advisory = OsvAdvisory(
        id="PRECVE-2026-00000002",
        modified=_CONFORMANCE_TS,
        published=_CONFORMANCE_TS,
        summary=f"Conformance already-patched advisory for {package_name}",
        affected=(
            OsvAffected(
                package=OsvPackage(ecosystem=ecosystem, name=package_name, purl=canonical_purl),
                ranges=(
                    OsvRange(
                        type="ECOSYSTEM",
                        events=(
                            OsvRangeEvent(introduced="0"),
                            OsvRangeEvent(fixed=safe_fixed),
                        ),
                    ),
                ),
            ),
        ),
    )
    unmatched_advisory = OsvAdvisory(
        id="PRECVE-2026-00000003",
        modified=_CONFORMANCE_TS,
        published=_CONFORMANCE_TS,
        summary="Conformance unmatched nonexistent package",
        affected=(
            OsvAffected(
                package=OsvPackage(
                    ecosystem="PyPI",
                    name="zerobom-nonexistent-conformance-pkg",
                    purl="pkg:pypi/zerobom-nonexistent-conformance-pkg",
                ),
                ranges=(
                    OsvRange(
                        type="ECOSYSTEM",
                        events=(
                            OsvRangeEvent(introduced="0"),
                            OsvRangeEvent(fixed="9.9.9"),
                        ),
                    ),
                ),
            ),
        ),
    )
    return BackendConformanceCase(
        expected_backend_name=backend_name,
        vulnerable_advisory=vulnerable_advisory,
        safe_advisory=safe_advisory,
        unmatched_advisory=unmatched_advisory,
    )


def assert_backend_conformance(
    backend: InventoryBackend,
    case: BackendConformanceCase,
) -> tuple[MatchResult, ...]:
    """Verify that an :class:`InventoryBackend` plugin fulfills every ZeroBOM contract invariant.

    Args:
        backend: Instantiated backend plugin under test.
        case: Parameterized conformance test case.

    Returns:
        Verified tuple of vulnerable :class:`MatchResult` hits from ``case.vulnerable_advisory``.

    Raises:
        BackendConformanceError: If any protocol, identifier, ``AssetRef``, deterministic
            ``univers`` version filtering, empty-query, or idempotency check fails.
    """
    if case.min_vulnerable_hits < 1:
        raise BackendConformanceError("BackendConformanceCase.min_vulnerable_hits must be >= 1.")

    if not isinstance(backend, InventoryBackend):
        raise BackendConformanceError(
            f"Backend {backend!r} does not implement the InventoryBackend protocol."
        )

    backend_name = backend.name
    if not isinstance(backend_name, str) or not _CONFORMANCE_BACKEND_NAME_RE.match(backend_name):
        raise BackendConformanceError(
            f"Backend.name {backend_name!r} must match ^[a-z][a-z0-9_-]{{0,63}}$."
        )
    if backend_name != case.expected_backend_name:
        raise BackendConformanceError(
            f"Expected backend.name={case.expected_backend_name!r}, got {backend_name!r}."
        )

    empty_results = backend.find_components(())
    if not isinstance(empty_results, Sequence) or len(empty_results) != 0:
        raise BackendConformanceError(
            f"find_components(()) must return an empty sequence, got {empty_results!r}."
        )

    vuln_queries = build_package_queries(case.vulnerable_advisory)
    raw_candidates = backend.find_components(vuln_queries)
    if not isinstance(raw_candidates, Sequence):
        raise BackendConformanceError(
            f"find_components() must return a sequence, got {type(raw_candidates).__name__}."
        )
    for comp in raw_candidates:
        if not isinstance(comp, InventoryComponent):
            raise BackendConformanceError(
                f"find_components() yielded non-InventoryComponent {comp!r}."
            )
        if comp.asset.backend != backend_name:
            raise BackendConformanceError(
                f"Component {comp.name}@{comp.version} has AssetRef.backend={comp.asset.backend!r},"
                f" expected {backend_name!r}."
            )

    vuln_matches = match_advisory_with_backend(
        case.vulnerable_advisory,
        backend,
        only_vulnerable=True,
    )
    if len(vuln_matches) < case.min_vulnerable_hits:
        raise BackendConformanceError(
            f"Expected at least {case.min_vulnerable_hits} vulnerable match(es) for "
            f"{case.vulnerable_advisory.id}, got {len(vuln_matches)}."
        )
    for match in vuln_matches:
        if not match.is_vulnerable:
            raise BackendConformanceError(
                f"only_vulnerable=True returned non-vulnerable match {match!r}."
            )
        if match.asset is None or match.asset.backend != backend_name:
            raise BackendConformanceError(
                f"Match {match.component_purl} missing consistent "
                f"AssetRef.backend={backend_name!r}."
            )

    safe_matches = match_advisory_with_backend(case.safe_advisory, backend, only_vulnerable=True)
    if safe_matches:
        raise BackendConformanceError(
            "Safe/patched advisory yielded false-positive vulnerable matches; version math must "
            "be handled via zerobom's univers evaluator."
        )

    unmatched_matches = match_advisory_with_backend(
        case.unmatched_advisory,
        backend,
        only_vulnerable=True,
    )
    if unmatched_matches:
        raise BackendConformanceError(
            f"Unmatched advisory yielded unexpected matches: {unmatched_matches!r}."
        )

    repeat_matches = match_advisory_with_backend(
        case.vulnerable_advisory,
        backend,
        only_vulnerable=True,
    )
    if vuln_matches != repeat_matches:
        raise BackendConformanceError(
            "Backend matching is non-idempotent across consecutive identical queries."
        )

    return vuln_matches
