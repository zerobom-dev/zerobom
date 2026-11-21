"""Cloud-agnostic inventory backend interfaces, plugin registry, parser, and conformance."""

from zerobom.backends.base import (
    BackendConfigError,
    BackendError,
    BackendLoadError,
    BackendQueryError,
    InventoryBackend,
    match_advisory_with_backend,
)
from zerobom.backends.conformance import (
    BackendConformanceCase,
    BackendConformanceError,
    assert_backend_conformance,
    build_default_conformance_case,
)
from zerobom.backends.dependency_track import DependencyTrackBackend
from zerobom.backends.k8s_sbom import K8sSbomBackend
from zerobom.backends.local_sbom import LocalSbomBackend, SbomParseError
from zerobom.backends.oci_sbom import OciSbomBackend
from zerobom.backends.registry import (
    BACKEND_ENTRY_POINT_GROUP,
    BackendRegistry,
    parse_backend_options,
)
from zerobom.backends.sbom_parser import (
    InMemoryComponentIndex,
    derive_sbom_asset,
    parse_cyclonedx_dict,
    parse_sbom_bytes,
    parse_spdx_dict,
)

__all__ = [
    "BACKEND_ENTRY_POINT_GROUP",
    "BackendConfigError",
    "BackendConformanceCase",
    "BackendConformanceError",
    "BackendError",
    "BackendLoadError",
    "BackendQueryError",
    "BackendRegistry",
    "DependencyTrackBackend",
    "InMemoryComponentIndex",
    "InventoryBackend",
    "K8sSbomBackend",
    "LocalSbomBackend",
    "OciSbomBackend",
    "SbomParseError",
    "assert_backend_conformance",
    "build_default_conformance_case",
    "derive_sbom_asset",
    "match_advisory_with_backend",
    "parse_backend_options",
    "parse_cyclonedx_dict",
    "parse_sbom_bytes",
    "parse_spdx_dict",
]
