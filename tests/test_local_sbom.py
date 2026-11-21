"""Comprehensive offline unit tests for cloud-agnostic backends and local SBOM matching."""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from zerobom.backends import (
    BackendLoadError,
    BackendRegistry,
    InMemoryComponentIndex,
    LocalSbomBackend,
    SbomParseError,
    match_advisory_with_backend,
)
from zerobom.backends.local_sbom import _is_path_within_root
from zerobom.models import (
    AssetRef,
    InventoryComponent,
    OsvAdvisory,
    OsvAffected,
    OsvPackage,
    OsvRange,
    OsvRangeEvent,
    PackageQuery,
)
from zerobom.verify import (
    evaluate_inventory_component,
    is_distro_compatible,
    normalize_distro_qualifier,
    parse_osv_ecosystem,
)

PUBLISHED_AT = datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC)


def _write_json(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _make_advisory(
    affected_entries: tuple[OsvAffected, ...],
    *,
    advisory_id: str = "PRECVE-2026-AABBCCDD",
) -> OsvAdvisory:
    return OsvAdvisory(
        id=advisory_id,
        modified=PUBLISHED_AT,
        published=PUBLISHED_AT,
        summary="Test pre-CVE advisory",
        affected=affected_entries,
        database_specific={"zerobom": {"evidence_quotes": ["affected prior to fixed release"]}},
    )


# ---------------------------------------------------------------------------
# 1. Cloud-Agnostic Inventory Contracts
# ---------------------------------------------------------------------------


class TestCloudAgnosticContracts:
    def test_asset_ref_bounds_and_strict_validation(self) -> None:
        asset = AssetRef(
            asset_id="sbom/api-service.cdx.json",
            asset_type="container_image",
            backend="local_sbom",
            scope="org/platform",
            location="docker/api-service/sbom.cdx.json",
            metadata={"cluster": "prod-eu", "digest": "sha256:abc123"},
        )
        assert asset.backend == "local_sbom"
        assert "account_id" not in AssetRef.model_fields
        assert "region" not in AssetRef.model_fields

        with pytest.raises(ValidationError):
            AssetRef(
                asset_id="id",
                asset_type="sbom",
                backend="local_sbom",
                account_id="123456789012",  # type: ignore[call-arg]
            )

        with pytest.raises(ValidationError):
            AssetRef(
                asset_id="bad\nid",
                asset_type="sbom",
                backend="local_sbom",
            )

        too_many = {f"k{i}": "v" for i in range(33)}
        with pytest.raises(ValidationError):
            AssetRef(
                asset_id="id",
                asset_type="sbom",
                backend="local_sbom",
                metadata=too_many,
            )

        with pytest.raises(ValidationError):
            AssetRef(
                asset_id="id",
                asset_type="sbom",
                backend="local_sbom",
                metadata={"k" * 65: "val"},
            )

        with pytest.raises(ValidationError):
            AssetRef(
                asset_id="id",
                asset_type="sbom",
                backend="local_sbom",
                metadata={"k": "v" * 513},
            )


# ---------------------------------------------------------------------------
# 2. CycloneDX (1.4 - 1.6) Parsing & Matching
# ---------------------------------------------------------------------------


class TestCycloneDxLocalSbom:
    def test_cyclonedx_recursive_metadata_and_multi_ecosystem_matching(
        self,
        tmp_path: Path,
    ) -> None:
        cdx_path = _write_json(
            tmp_path / "service.cdx.json",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "metadata": {
                    "component": {
                        "type": "application",
                        "name": "edge-gateway",
                        "version": "1.9.1",
                        "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
                        "bom-ref": "root-app",
                    }
                },
                "components": [
                    {
                        "type": "library",
                        "name": "Requests",
                        "version": "2.30.0",
                        "purl": "pkg:pypi/Requests@2.30.0",
                        "components": [
                            {
                                "type": "library",
                                "name": "@babel/traverse",
                                "purl": "pkg:npm/%40babel/traverse@7.23.1",
                            }
                        ],
                    },
                    {
                        "type": "library",
                        "group": "org.apache.logging.log4j",
                        "name": "log4j-core",
                        "version": "2.14.1",
                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                    },
                ],
            },
        )

        backend = LocalSbomBackend(cdx_path)
        assert backend.name == "local_sbom"
        assert len(backend.components) == 4
        assert backend.loaded_files == (cdx_path,)

        advisory = _make_advisory(
            (
                OsvAffected(
                    package=OsvPackage(ecosystem="PyPI", name="requests", purl="pkg:pypi/requests"),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(OsvRangeEvent(introduced="0"), OsvRangeEvent(fixed="2.31.0")),
                        ),
                    ),
                ),
                OsvAffected(
                    package=OsvPackage(
                        ecosystem="npm",
                        name="@babel/traverse",
                        purl="pkg:npm/%40babel/traverse",
                    ),
                    ranges=(
                        OsvRange(
                            type="SEMVER",
                            events=(OsvRangeEvent(introduced="0"), OsvRangeEvent(fixed="7.23.2")),
                        ),
                    ),
                ),
                OsvAffected(
                    package=OsvPackage(
                        ecosystem="Maven",
                        name="org.apache.logging.log4j:log4j-core",
                        purl="pkg:maven/org.apache.logging.log4j/log4j-core",
                    ),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(
                                OsvRangeEvent(introduced="2.0-beta9"),
                                OsvRangeEvent(fixed="2.15.0"),
                            ),
                        ),
                    ),
                ),
                OsvAffected(
                    package=OsvPackage(
                        ecosystem="Go",
                        name="github.com/gin-gonic/gin",
                        purl="pkg:golang/github.com/gin-gonic/gin",
                    ),
                    ranges=(
                        OsvRange(
                            type="SEMVER",
                            events=(
                                OsvRangeEvent(introduced="v1.0.0"),
                                OsvRangeEvent(fixed="v1.10.0"),
                            ),
                        ),
                    ),
                ),
            )
        )

        matches = match_advisory_with_backend(advisory, backend)
        assert len(matches) == 4
        matched_purls = {m.matched_purl for m in matches}
        assert matched_purls == {
            "pkg:pypi/requests",
            "pkg:npm/%40babel/traverse",
            "pkg:maven/org.apache.logging.log4j/log4j-core",
            "pkg:golang/github.com/gin-gonic/gin",
        }
        assert all(m.is_vulnerable for m in matches)
        assert all(m.asset is not None and m.asset.scope == "edge-gateway" for m in matches)

    def test_cyclonedx_excessive_nesting_depth_rejected(self, tmp_path: Path) -> None:
        deep_node: dict[str, Any] = {"type": "library", "name": "leaf", "version": "1.0.0"}
        for i in range(5):
            deep_node = {
                "type": "library",
                "name": f"layer-{i}",
                "version": "1.0.0",
                "components": [deep_node],
            }
        cdx_path = _write_json(
            tmp_path / "deep.cdx.json",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [deep_node],
            },
        )
        with pytest.raises(SbomParseError, match="max depth"):
            LocalSbomBackend(cdx_path, max_depth=3)


# ---------------------------------------------------------------------------
# 3. SPDX 2.3 Parsing & Safe Name Fallback
# ---------------------------------------------------------------------------


class TestSpdxLocalSbom:
    def test_spdx_external_refs_sentinels_and_safe_fallback(self, tmp_path: Path) -> None:
        spdx_path = _write_json(
            tmp_path / "app.spdx.json",
            {
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "web-app",
                "packages": [
                    {
                        "SPDXID": "SPDXRef-pkg-1",
                        "name": "requests",
                        "versionInfo": "2.30.0",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:pypi/requests@2.30.0",
                            }
                        ],
                    },
                    {
                        "SPDXID": "SPDXRef-pkg-2",
                        "name": "lodash",
                        "versionInfo": "4.17.20",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE_MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:npm/lodash@4.17.20",
                            }
                        ],
                    },
                    {
                        "SPDXID": "SPDXRef-pkg-3",
                        "name": "Django_Rest_Framework",
                        "versionInfo": "3.14.0",
                    },
                    {
                        "SPDXID": "SPDXRef-pkg-4",
                        "name": "utils",
                        "versionInfo": "1.0.0",
                    },
                    {
                        "SPDXID": "SPDXRef-pkg-5",
                        "name": "unversioned-pkg",
                        "versionInfo": "NOASSERTION",
                    },
                ],
            },
        )

        backend = LocalSbomBackend(spdx_path)
        # unversioned-pkg (NOASSERTION) is ignored -> 4 indexed components.
        assert len(backend.components) == 4

        advisory = _make_advisory(
            (
                OsvAffected(
                    package=OsvPackage(ecosystem="PyPI", name="requests", purl="pkg:pypi/requests"),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(OsvRangeEvent(introduced="0"), OsvRangeEvent(fixed="2.31.0")),
                        ),
                    ),
                ),
                OsvAffected(
                    package=OsvPackage(ecosystem="npm", name="lodash", purl="pkg:npm/lodash"),
                    ranges=(
                        OsvRange(
                            type="SEMVER",
                            events=(OsvRangeEvent(introduced="0"), OsvRangeEvent(fixed="4.17.21")),
                        ),
                    ),
                ),
                OsvAffected(
                    package=OsvPackage(
                        ecosystem="PyPI",
                        name="django-rest-framework",
                        purl="pkg:pypi/django-rest-framework",
                    ),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(OsvRangeEvent(introduced="0"), OsvRangeEvent(fixed="3.15.2")),
                        ),
                    ),
                ),
                OsvAffected(
                    package=OsvPackage(ecosystem="npm", name="utils", purl="pkg:npm/utils"),
                    ranges=(
                        OsvRange(
                            type="SEMVER",
                            events=(OsvRangeEvent(introduced="0"), OsvRangeEvent(fixed="2.0.0")),
                        ),
                    ),
                ),
            )
        )

        matches = match_advisory_with_backend(advisory, backend)
        by_purl = {m.matched_purl: m for m in matches}
        assert set(by_purl.keys()) == {
            "pkg:pypi/requests",
            "pkg:npm/lodash",
            "pkg:pypi/django-rest-framework",
        }
        assert by_purl["pkg:pypi/requests"].matched_via == "purl"
        assert by_purl["pkg:npm/lodash"].matched_via == "purl"
        assert by_purl["pkg:pypi/django-rest-framework"].matched_via == "name_fallback"
        # Generic package name "utils" without a PURL must never match via name fallback.
        assert "pkg:npm/utils" not in by_purl

    def test_name_fallback_uses_ecosystem_aware_blocklist(self) -> None:
        asset = AssetRef(backend="local_sbom", asset_id="host-1", asset_type="sbom")
        components = (
            InventoryComponent(
                asset=asset,
                name="kernel",
                version="5.14.0-600.1.el9_8",
                ecosystem="rpm",
            ),
            InventoryComponent(
                asset=asset,
                name="ruby",
                version="3.4.1",
                ecosystem="generic",
            ),
            InventoryComponent(
                asset=asset,
                name="ruby",
                version="1.0.0",
                ecosystem="gem",
            ),
            InventoryComponent(
                asset=asset,
                name="utils",
                version="1.0.0",
                ecosystem="deb",
            ),
        )
        advisory = OsvAdvisory(
            id="PRECVE-2026-ECOBLOCK",
            modified=PUBLISHED_AT,
            published=PUBLISHED_AT,
            summary="Ecosystem-aware name fallback matching test.",
            affected=(
                OsvAffected(
                    package=OsvPackage(
                        ecosystem="CloudLinux",
                        name="kernel",
                        purl="pkg:rpm/cloudlinux/kernel",
                    ),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(
                                OsvRangeEvent(introduced="0"),
                                OsvRangeEvent(fixed="5.14.0-687.60.1.el9_8"),
                            ),
                        ),
                    ),
                ),
                OsvAffected(
                    package=OsvPackage(ecosystem="Generic", name="ruby", purl="pkg:generic/ruby"),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(
                                OsvRangeEvent(introduced="3.4.0"),
                                OsvRangeEvent(fixed="3.4.2"),
                            ),
                        ),
                    ),
                ),
                OsvAffected(
                    package=OsvPackage(ecosystem="RubyGems", name="ruby", purl="pkg:gem/ruby"),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(OsvRangeEvent(introduced="0"), OsvRangeEvent(fixed="2.0.0")),
                        ),
                    ),
                ),
                OsvAffected(
                    package=OsvPackage(
                        ecosystem="Debian", name="utils", purl="pkg:deb/debian/utils"
                    ),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(OsvRangeEvent(introduced="0"), OsvRangeEvent(fixed="2.0.0")),
                        ),
                    ),
                ),
            ),
        )

        matched = [evaluate_inventory_component(advisory, comp) for comp in components]
        matched_purls = {
            res.matched_purl for res in matched if res is not None and res.is_vulnerable
        }
        assert matched_purls == {"pkg:rpm/cloudlinux/kernel", "pkg:generic/ruby"}


# ---------------------------------------------------------------------------
# 4. Directory Scanning & Security Defenses
# ---------------------------------------------------------------------------


class TestDirectoryScanAndSecurity:
    def test_directory_scan_skips_non_sbom_json_and_handles_errors(
        self,
        tmp_path: Path,
    ) -> None:
        sbom_dir = tmp_path / "sboms"
        _write_json(
            sbom_dir / "a" / "app.cdx.json",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "components": [
                    {
                        "type": "library",
                        "name": "requests",
                        "version": "2.30.0",
                        "purl": "pkg:pypi/requests@2.30.0",
                    }
                ],
            },
        )
        _write_json(
            sbom_dir / "b" / "lib.spdx.json",
            {
                "spdxVersion": "SPDX-2.2",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "lib",
                "packages": [
                    {
                        "SPDXID": "SPDXRef-1",
                        "name": "urllib3",
                        "versionInfo": "1.26.15",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:pypi/urllib3@1.26.15",
                            }
                        ],
                    }
                ],
            },
        )
        non_sbom = _write_json(
            sbom_dir / "package.json",
            {"name": "frontend", "version": "1.0.0"},
        )

        backend = LocalSbomBackend(sbom_dir)
        assert len(backend.loaded_files) == 2
        assert backend.skipped_files == (non_sbom,)
        assert len(backend.components) == 2

        # Explicit non-SBOM JSON raises SbomParseError.
        with pytest.raises(SbomParseError, match="Unrecognized SBOM"):
            LocalSbomBackend(non_sbom)

        # Malformed JSON raises SbomParseError.
        bad_json = tmp_path / "broken.cdx.json"
        bad_json.write_text("{not-json", encoding="utf-8")
        with pytest.raises(SbomParseError, match="Invalid JSON"):
            LocalSbomBackend(bad_json)

        # Oversized file raises SbomParseError.
        with pytest.raises(SbomParseError, match="exceeds maximum size"):
            LocalSbomBackend(sbom_dir / "a" / "app.cdx.json", max_file_bytes=20)

        # Exceeding max_files raises SbomParseError.
        with pytest.raises(SbomParseError, match="exceeding max_files"):
            LocalSbomBackend(sbom_dir, max_files=2)

    def test_path_containment_and_symlink_escape_defense(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        root = tmp_path / "root"
        inside = root / "nested" / "sbom.json"
        outside = tmp_path / "secret.json"
        root.mkdir()
        _write_json(
            outside,
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [{"type": "library", "name": "requests", "version": "2.30.0"}],
            },
        )

        assert _is_path_within_root(inside, root) is True
        assert _is_path_within_root(outside, root) is False

        symlink_path = root / "escape.cdx.json"
        try:
            os.symlink(outside, symlink_path)
        except OSError:
            # Windows without Developer Mode blocks symlink creation; test symlink-guard
            # behavior via a regular file flagged by monkeypatch.
            _write_json(
                symlink_path,
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "components": [{"type": "library", "name": "requests", "version": "2.30.0"}],
                },
            )
            real_is_symlink = Path.is_symlink

            def _fake_is_symlink(self_path: Path) -> bool:
                if self_path == symlink_path:
                    return True
                return real_is_symlink(self_path)

            monkeypatch.setattr(Path, "is_symlink", _fake_is_symlink)

        backend = LocalSbomBackend(root)
        assert symlink_path in backend.skipped_files
        assert len(backend.loaded_files) == 0


# ---------------------------------------------------------------------------
# 5. OS Distro Releases & ?upstream= Source Package Matching
# ---------------------------------------------------------------------------


class TestOsDistroAndUpstreamMatching:
    def test_distro_normalization_and_compatibility(self) -> None:
        assert parse_osv_ecosystem("Debian:11") == ("Debian", "debian-11")
        assert parse_osv_ecosystem("Ubuntu:22.04") == ("Ubuntu", "ubuntu-22.04")
        assert parse_osv_ecosystem("Alpine:v3.19") == ("Alpine", "alpine-3.19")
        assert parse_osv_ecosystem("Red Hat:enterprise_linux:9") == ("Red Hat", "rhel-9")
        assert parse_osv_ecosystem("PyPI") == ("PyPI", None)

        assert normalize_distro_qualifier("debian-11.8") == "debian-11"
        assert normalize_distro_qualifier("alpine-3.19.1") == "alpine-3.19"
        assert normalize_distro_qualifier("bookworm") == "debian-12"

        assert is_distro_compatible("debian-11", "debian-11.8") is True
        assert is_distro_compatible("debian-11", "debian-12") is False
        assert is_distro_compatible(None, "debian-11") is True
        assert is_distro_compatible("debian-11", None) is True

    def test_debian_and_alpine_upstream_and_cross_distro_isolation(self, tmp_path: Path) -> None:
        sbom_path = _write_json(
            tmp_path / "containers.cdx.json",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "type": "library",
                        "name": "libssl1.1",
                        "version": "1.1.1n-0+deb11u4",
                        "purl": (
                            "pkg:deb/debian/libssl1.1@1.1.1n-0%2Bdeb11u4"
                            "?distro=debian-11&upstream=openssl"
                        ),
                    },
                    {
                        "type": "library",
                        "name": "libssl1.1-explicit-up-ver",
                        "version": "0.1",
                        "purl": (
                            "pkg:deb/debian/libssl1.1@0.1"
                            "?distro=debian-11&upstream=openssl%401.1.1n-0%2Bdeb11u4"
                        ),
                    },
                    {
                        "type": "library",
                        "name": "libssl3",
                        "version": "1.1.1n-0+deb11u4",
                        "purl": (
                            "pkg:deb/debian/libssl3@1.1.1n-0%2Bdeb11u4"
                            "?distro=debian-12&upstream=openssl"
                        ),
                    },
                    {
                        "type": "library",
                        "name": "libcrypto3",
                        "version": "3.1.4-r4",
                        "purl": (
                            "pkg:apk/alpine/libcrypto3@3.1.4-r4"
                            "?distro=alpine-3.19.1&upstream=openssl"
                        ),
                    },
                    {
                        "type": "library",
                        "name": "libcrypto3",
                        "version": "3.1.4-r4",
                        "purl": (
                            "pkg:apk/alpine/libcrypto3@3.1.4-r4?distro=alpine-3.20&upstream=openssl"
                        ),
                    },
                ],
            },
        )
        backend = LocalSbomBackend(sbom_path)

        deb11_advisory = _make_advisory(
            (
                OsvAffected(
                    package=OsvPackage(
                        ecosystem="Debian:11",
                        name="openssl",
                        purl="pkg:deb/debian/openssl",
                    ),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(
                                OsvRangeEvent(introduced="0"),
                                OsvRangeEvent(fixed="1.1.1n-0+deb11u5"),
                            ),
                        ),
                    ),
                ),
                OsvAffected(
                    package=OsvPackage(
                        ecosystem="Alpine:v3.19",
                        name="openssl",
                        purl="pkg:apk/alpine/openssl",
                    ),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(
                                OsvRangeEvent(introduced="0"),
                                OsvRangeEvent(fixed="3.1.4-r5"),
                            ),
                        ),
                    ),
                ),
            )
        )

        matches = match_advisory_with_backend(deb11_advisory, backend)
        assert len(matches) == 3
        assert all(m.matched_via == "upstream" for m in matches)
        # Ensure debian-12 and alpine-3.20 components did NOT match Debian:11 / Alpine:v3.19.
        comp_purls = {m.component_purl for m in matches}
        assert not any("debian-12" in p for p in comp_purls)
        assert not any("alpine-3.20" in p for p in comp_purls)

        # Release-agnostic "Debian" matches debian-11 as well.
        deb_any_advisory = _make_advisory(
            (
                OsvAffected(
                    package=OsvPackage(
                        ecosystem="Debian",
                        name="openssl",
                        purl="pkg:deb/debian/openssl",
                    ),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(
                                OsvRangeEvent(introduced="0"),
                                OsvRangeEvent(fixed="1.1.1n-0+deb11u5"),
                            ),
                        ),
                    ),
                ),
            )
        )
        any_matches = match_advisory_with_backend(deb_any_advisory, backend)
        assert len(any_matches) == 3


# ---------------------------------------------------------------------------
# 6. Plugin Registry (zerobom.backends) & End-to-End Backend Matching
# ---------------------------------------------------------------------------


class _FakeEntryPoint:
    def __init__(self, name: str, loader: Any) -> None:
        self.name = name
        self._loader = loader

    def load(self) -> Any:
        return self._loader()


class _MockCloudPluginBackend:
    """Simulated third-party cloud inventory plugin using cloud-agnostic AssetRef."""

    def __init__(self, scope: str = "prod-org") -> None:
        self._scope = scope

    @property
    def name(self) -> str:
        return "mock_cloud"

    def find_components(self, queries: Sequence[PackageQuery]) -> tuple[InventoryComponent, ...]:
        asset = AssetRef(
            asset_id="cloud-asset://cluster-1/workload-api",
            asset_type="container_image",
            backend=self.name,
            scope=self._scope,
            location="eu-west-1",
            metadata={"provider_kind": "cloud_plugin"},
        )
        out: list[InventoryComponent] = []
        for q in queries:
            if q.canonical_purl == "pkg:pypi/requests":
                out.append(
                    InventoryComponent(
                        name="requests",
                        version="2.30.0",
                        purl="pkg:pypi/requests@2.30.0",
                        canonical_purl="pkg:pypi/requests",
                        ecosystem="pypi",
                        asset=asset,
                    )
                )
                out.append(
                    InventoryComponent(
                        name="requests",
                        version="2.31.0",
                        purl="pkg:pypi/requests@2.31.0",
                        canonical_purl="pkg:pypi/requests",
                        ecosystem="pypi",
                        asset=AssetRef(
                            asset_id="cloud-asset://cluster-1/workload-patched",
                            asset_type="container_image",
                            backend=self.name,
                            scope=self._scope,
                        ),
                    )
                )
        return tuple(out)


class TestBackendRegistryAndPlugins:
    def test_builtin_local_sbom_discovery_and_creation(self, tmp_path: Path) -> None:
        cdx_path = _write_json(
            tmp_path / "sbom.cdx.json",
            {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []},
        )
        registry = BackendRegistry()
        assert "local_sbom" in registry.list_backends()
        backend = registry.create("local_sbom", paths=cdx_path)
        assert isinstance(backend, LocalSbomBackend)
        assert backend.name == "local_sbom"

    def test_plugin_discovery_broken_entry_points_and_filtering(self) -> None:
        def broken_loader() -> Any:
            raise ImportError("missing optional cloud SDK")

        registry = BackendRegistry(
            entry_points_provider=lambda _group: [
                _FakeEntryPoint("mock_cloud", lambda: _MockCloudPluginBackend),
                _FakeEntryPoint("broken_plugin", broken_loader),
                _FakeEntryPoint("bad_protocol", lambda: lambda: object()),
                _FakeEntryPoint("INVALID NAME!", lambda: _MockCloudPluginBackend),
            ]
        )

        backends = registry.list_backends()
        assert backends == ("bad_protocol", "broken_plugin", "local_sbom", "mock_cloud")

        with pytest.raises(BackendLoadError, match="missing optional cloud SDK"):
            registry.create("broken_plugin")

        with pytest.raises(BackendLoadError, match="InventoryBackend"):
            registry.create("bad_protocol")

        with pytest.raises(BackendLoadError, match="Unknown inventory backend"):
            registry.create("nonexistent")

        cloud_backend = registry.create("mock_cloud", scope="tenant-42")
        advisory = _make_advisory(
            (
                OsvAffected(
                    package=OsvPackage(ecosystem="PyPI", name="requests", purl="pkg:pypi/requests"),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(OsvRangeEvent(introduced="0"), OsvRangeEvent(fixed="2.31.0")),
                        ),
                    ),
                ),
            )
        )

        vuln_only = match_advisory_with_backend(advisory, cloud_backend, only_vulnerable=True)
        assert len(vuln_only) == 1
        assert vuln_only[0].installed_version == "2.30.0"
        assert vuln_only[0].asset is not None
        assert vuln_only[0].asset.scope == "tenant-42"
        assert vuln_only[0].asset.metadata == {"provider_kind": "cloud_plugin"}

        all_eval = match_advisory_with_backend(advisory, cloud_backend, only_vulnerable=False)
        assert len(all_eval) == 2
        assert {m.is_vulnerable for m in all_eval} == {True, False}

    def test_namespaced_purl_less_fallback_and_multi_branch_advisory(self) -> None:
        asset = AssetRef(backend="local_sbom", asset_id="svc-a/sbom.cdx.json", asset_type="sbom")

        # 1) Explicit namespace allows PURL-less match even on generic artifact name ("utils").
        maven_comp = InventoryComponent(
            asset=asset,
            name="utils",
            namespace="com.acme",
            version="1.0.0",
            ecosystem="maven",
        )
        # 2) Bare unnamespaced name ("traverse") must NOT match scoped @babel/traverse.
        bare_npm = InventoryComponent(
            asset=asset,
            name="traverse",
            namespace=None,
            version="7.20.0",
            ecosystem="npm",
        )

        index = InMemoryComponentIndex()
        index.add_components((maven_comp, bare_npm))

        maven_query = PackageQuery(
            canonical_purl="pkg:maven/com.acme/utils",
            ecosystem="maven",
            osv_ecosystem="Maven",
            name="utils",
            namespace="com.acme",
        )
        babel_query = PackageQuery(
            canonical_purl="pkg:npm/%40babel/traverse",
            ecosystem="npm",
            osv_ecosystem="npm",
            name="traverse",
            namespace="@babel",
        )
        assert index.find_components((maven_query,)) == (maven_comp,)
        assert index.find_components((babel_query,)) == ()

        maven_advisory = _make_advisory(
            (
                OsvAffected(
                    package=OsvPackage(
                        ecosystem="Maven",
                        name="com.acme:utils",
                        purl="pkg:maven/com.acme/utils",
                    ),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(OsvRangeEvent(introduced="0"), OsvRangeEvent(fixed="1.2.0")),
                        ),
                    ),
                ),
            ),
            advisory_id="PRECVE-2026-MVNNS",
        )
        npm_scoped_advisory = _make_advisory(
            (
                OsvAffected(
                    package=OsvPackage(
                        ecosystem="npm",
                        name="@babel/traverse",
                        purl="pkg:npm/%40babel/traverse",
                    ),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(OsvRangeEvent(introduced="0"), OsvRangeEvent(fixed="7.23.2")),
                        ),
                    ),
                ),
            ),
            advisory_id="PRECVE-2026-NPMSCOPE",
        )

        maven_hit = evaluate_inventory_component(maven_advisory, maven_comp)
        assert maven_hit is not None
        assert maven_hit.is_vulnerable is True
        assert evaluate_inventory_component(npm_scoped_advisory, bare_npm) is None

        # 3) Multi-branch advisory for same canonical PURL: earlier non-vulnerable branch
        # must NOT shadow a later vulnerable branch.
        multi_branch = _make_advisory(
            (
                OsvAffected(
                    package=OsvPackage(
                        ecosystem="PyPI",
                        name="requests",
                        purl="pkg:pypi/requests",
                    ),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(
                                OsvRangeEvent(introduced="1.0.0"),
                                OsvRangeEvent(fixed="1.5.0"),
                            ),
                        ),
                    ),
                ),
                OsvAffected(
                    package=OsvPackage(
                        ecosystem="PyPI",
                        name="requests",
                        purl="pkg:pypi/requests",
                    ),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(
                                OsvRangeEvent(introduced="2.0.0"),
                                OsvRangeEvent(fixed="2.31.0"),
                            ),
                        ),
                    ),
                ),
            ),
            advisory_id="PRECVE-2026-BRANCH",
        )

        purl_comp = InventoryComponent(
            asset=asset,
            name="requests",
            version="2.30.0",
            purl="pkg:pypi/requests@2.30.0",
            ecosystem="pypi",
        )
        purl_res = evaluate_inventory_component(multi_branch, purl_comp)
        assert purl_res is not None
        assert purl_res.is_vulnerable is True

        purlless_comp = InventoryComponent(
            asset=asset,
            name="requests",
            version="2.30.0",
            ecosystem="pypi",
        )
        purlless_res = evaluate_inventory_component(multi_branch, purlless_comp)
        assert purlless_res is not None
        assert purlless_res.is_vulnerable is True

    def test_local_sbom_rejects_deep_json_recursion_error(self, tmp_path: Path) -> None:
        deep_path = tmp_path / "deep.cdx.json"
        deep_path.write_text("[" * 2000 + "]" * 2000, encoding="utf-8")
        with pytest.raises(SbomParseError, match="Invalid JSON"):
            LocalSbomBackend(deep_path)
