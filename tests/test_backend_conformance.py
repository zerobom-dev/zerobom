"""Offline unit tests for Milestone 2.1A backend foundation, conformance harness, and SARIF."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from zerobom.backends import (
    BackendConfigError,
    BackendConformanceError,
    BackendLoadError,
    BackendRegistry,
    InMemoryComponentIndex,
    LocalSbomBackend,
    SbomParseError,
    assert_backend_conformance,
    build_default_conformance_case,
    parse_backend_options,
    parse_sbom_bytes,
)
from zerobom.models import (
    AssetRef,
    InventoryComponent,
    OsvAdvisory,
    OsvAffected,
    OsvPackage,
    OsvRange,
    OsvRangeEvent,
    PackageQuery,
    PipelineOutcome,
)
from zerobom.outputs import build_sarif_log

PUBLISHED_AT = datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)


def _sample_cdx_bytes(*, version: str = "2.30.0") -> bytes:
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
        "metadata": {
            "component": {
                "type": "container",
                "name": "payments-api",
                "version": "1.0.0",
            }
        },
        "components": [
            {
                "type": "library",
                "name": "requests",
                "version": version,
                "purl": f"pkg:pypi/requests@{version}",
                "components": [
                    {
                        "type": "library",
                        "name": "urllib3",
                        "version": "1.26.18",
                        "purl": "pkg:pypi/urllib3@1.26.18",
                    }
                ],
            },
            {
                "type": "library",
                "name": "openssl-dev",
                "version": "1.1.1n",
                "purl": "pkg:deb/debian/libssl1.1@1.1.1n?distro=debian-11&upstream=openssl",
            },
        ],
    }
    return json.dumps(payload).encode("utf-8")


def _sample_spdx_bytes() -> bytes:
    payload = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "billing-worker",
        "documentNamespace": "https://example.org/spdx/billing-worker",
        "packages": [
            {
                "SPDXID": "SPDXRef-pkg-1",
                "name": "Requests",
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
                "name": "no-version-pkg",
                "versionInfo": "NOASSERTION",
            },
        ],
    }
    return json.dumps(payload).encode("utf-8")


class TestCloudAgnosticSbomParserAndIndex:
    def test_parse_sbom_bytes_cyclonedx_and_spdx_with_safe_metadata(self) -> None:
        cdx_comps = parse_sbom_bytes(
            _sample_cdx_bytes(),
            asset_id="s3://sec-bucket/payments/sbom.cdx.json",
            backend="s3_sbom",
            location="s3://sec-bucket/payments/sbom.cdx.json",
            extra_metadata={
                "bucket": "sec-bucket",
                "bad\nkey": "ignored",
                "ok": "bad\x00value",
            },
        )
        assert len(cdx_comps) == 4
        asset = cdx_comps[0].asset
        assert asset.backend == "s3_sbom"
        assert asset.asset_type == "container"
        assert asset.scope == "payments-api"
        assert asset.metadata["format"] == "cyclonedx"
        assert asset.metadata["bucket"] == "sec-bucket"
        assert "bad\nkey" not in asset.metadata
        assert "ok" not in asset.metadata

        spdx_comps = parse_sbom_bytes(
            _sample_spdx_bytes(),
            asset_id="oci://ghcr.io/org/billing@sha256:abc123",
            backend="oci_sbom",
            location="oci://ghcr.io/org/billing@sha256:abc123",
            extra_metadata={"digest": "sha256:abc123"},
        )
        assert len(spdx_comps) == 1
        assert spdx_comps[0].canonical_purl == "pkg:pypi/requests"
        assert spdx_comps[0].asset.backend == "oci_sbom"
        assert spdx_comps[0].asset.scope == "billing-worker"
        assert spdx_comps[0].asset.metadata["format"] == "spdx"
        assert spdx_comps[0].asset.metadata["digest"] == "sha256:abc123"

        index = InMemoryComponentIndex(cdx_comps)
        assert len(index.components) == 4
        by_purl = index.find_components(
            (
                PackageQuery(
                    canonical_purl="pkg:pypi/urllib3",
                    ecosystem="pypi",
                    osv_ecosystem="PyPI",
                    name="urllib3",
                ),
            )
        )
        assert len(by_purl) == 1
        assert by_purl[0].version == "1.26.18"

        by_upstream = index.find_components(
            (
                PackageQuery(
                    canonical_purl="pkg:deb/debian/openssl",
                    ecosystem="deb",
                    osv_ecosystem="Debian:11",
                    namespace="debian",
                    name="openssl",
                    distro_release="debian-11",
                ),
            )
        )
        assert len(by_upstream) == 1
        assert by_upstream[0].upstream_package == "openssl"

    def test_parse_sbom_bytes_enforces_size_depth_and_schema_bounds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        raw = _sample_cdx_bytes()
        with pytest.raises(SbomParseError, match="exceeds maximum size"):
            parse_sbom_bytes(raw, asset_id="mem://big", backend="oci_sbom", max_bytes=32)

        with pytest.raises(SbomParseError, match="Invalid JSON"):
            parse_sbom_bytes(b"{not-json", asset_id="mem://bad", backend="oci_sbom")

        with pytest.raises(SbomParseError, match="must be a JSON object"):
            parse_sbom_bytes(b"[]", asset_id="mem://arr", backend="oci_sbom")

        with pytest.raises(SbomParseError, match="Unrecognized SBOM schema"):
            parse_sbom_bytes(b'{"hello": "world"}', asset_id="mem://unk", backend="oci_sbom")

        deep_cdx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "name": "top",
                    "version": "1.0.0",
                    "components": [
                        {
                            "name": "child",
                            "version": "1.0.0",
                            "components": [{"name": "grandchild", "version": "1.0.0"}],
                        }
                    ],
                }
            ],
        }
        with pytest.raises(SbomParseError, match="exceeds max depth 1"):
            parse_sbom_bytes(
                json.dumps(deep_cdx).encode("utf-8"),
                asset_id="mem://deep",
                backend="oci_sbom",
                max_depth=1,
            )

        deep_raw = ("[" * 2000 + "]" * 2000).encode("utf-8")
        with pytest.raises(SbomParseError, match=r"Invalid JSON|must be a JSON object"):
            parse_sbom_bytes(deep_raw, asset_id="mem://deep-list", backend="oci_sbom")

        def _raise_recursion(*_args: object, **_kwargs: object) -> object:
            raise RecursionError("maximum recursion depth exceeded")

        monkeypatch.setattr(json, "loads", _raise_recursion)
        with pytest.raises(SbomParseError, match="Invalid JSON"):
            parse_sbom_bytes(b"{}", asset_id="mem://recursion", backend="oci_sbom")


class TestBackendConfigAndRegistryHooks:
    def test_parse_backend_options_and_from_config_lifecycle(self, tmp_path: Path) -> None:
        sbom_a = tmp_path / "a.cdx.json"
        sbom_b = tmp_path / "b.cdx.json"
        sbom_a.write_bytes(_sample_cdx_bytes(version="2.30.0"))
        sbom_b.write_bytes(_sample_spdx_bytes())

        cfg_yaml = tmp_path / "backend.yaml"
        cfg_yaml.write_text(
            f"options:\n  paths: {sbom_a}\n  max_files: 10\n",
            encoding="utf-8",
        )

        # CLI repeated options override YAML paths cleanly.
        parsed = parse_backend_options(
            (f"paths={sbom_a}", f"paths={sbom_b}", "max_files=25"),
            config_path=cfg_yaml,
        )
        assert parsed["paths"] == [str(sbom_a), str(sbom_b)]
        assert parsed["max_files"] == "25"

        backend = BackendRegistry().create("local_sbom", config=parsed)
        assert isinstance(backend, LocalSbomBackend)
        assert len(backend.loaded_files) == 2

        with pytest.raises(BackendConfigError, match="KEY=VALUE"):
            parse_backend_options(("missing_equals",))

        with pytest.raises(BackendConfigError, match="control characters"):
            parse_backend_options(("paths=ok\nnewline",))

        with pytest.raises(BackendConfigError, match="does not exist"):
            parse_backend_options(config_path=tmp_path / "nope.yaml")

        with pytest.raises(BackendConfigError, match="positive integer"):
            LocalSbomBackend.from_config({"paths": str(sbom_a), "max_files": True})

        with pytest.raises(BackendConfigError, match="requires 'paths'"):
            BackendRegistry().create("local_sbom", config={})


class TestBackendConformanceHarness:
    def test_local_sbom_and_custom_plugin_pass_conformance(self, tmp_path: Path) -> None:
        sbom_path = tmp_path / "app.cdx.json"
        sbom_path.write_bytes(_sample_cdx_bytes(version="2.30.0"))
        local_backend = LocalSbomBackend(sbom_path)

        case = build_default_conformance_case(
            backend_name="local_sbom",
            package_name="requests",
            ecosystem="PyPI",
            canonical_purl="pkg:pypi/requests",
            vulnerable_fixed="2.31.0",
            safe_fixed="1.0.0",
        )
        matches = assert_backend_conformance(local_backend, case)
        assert len(matches) == 1
        assert matches[0].installed_version == "2.30.0"

    def test_conformance_rejects_broken_and_noncompliant_backends(self) -> None:
        valid_asset = AssetRef(asset_id="asset-1", asset_type="sbom", backend="custom_api")
        valid_comp = InventoryComponent(
            name="requests",
            version="2.30.0",
            purl="pkg:pypi/requests@2.30.0",
            canonical_purl="pkg:pypi/requests",
            ecosystem="pypi",
            asset=valid_asset,
        )

        class _WrongAssetBackend:
            name = "custom_api"

            def find_components(
                self, queries: Sequence[PackageQuery]
            ) -> tuple[InventoryComponent, ...]:
                if not queries:
                    return ()
                wrong = valid_comp.model_copy(
                    update={"asset": AssetRef(asset_id="x", asset_type="sbom", backend="other")}
                )
                return (wrong,)

        case = build_default_conformance_case(backend_name="custom_api")
        with pytest.raises(BackendConformanceError, match=r"AssetRef\.backend"):
            assert_backend_conformance(_WrongAssetBackend(), case)

        class _NonEmptyOnEmptyQueriesBackend:
            name = "custom_api"

            def find_components(
                self, queries: Sequence[PackageQuery]
            ) -> tuple[InventoryComponent, ...]:
                del queries
                return (valid_comp,)

        with pytest.raises(BackendConformanceError, match="empty sequence"):
            assert_backend_conformance(_NonEmptyOnEmptyQueriesBackend(), case)

        class _NonIdempotentBackend:
            name = "custom_api"

            def __init__(self) -> None:
                self._calls = 0

            def find_components(
                self, queries: Sequence[PackageQuery]
            ) -> tuple[InventoryComponent, ...]:
                if not queries:
                    return ()
                self._calls += 1
                ver = "2.30.0" if self._calls <= 2 else "2.29.0"
                return (valid_comp.model_copy(update={"version": ver}),)

        with pytest.raises(BackendConformanceError, match="non-idempotent"):
            assert_backend_conformance(_NonIdempotentBackend(), case)

        class _InvalidNameBackend:
            name = "Invalid Name!"

            def find_components(
                self, queries: Sequence[PackageQuery]
            ) -> tuple[InventoryComponent, ...]:
                del queries
                return ()

        with pytest.raises(BackendConformanceError, match=r"Backend\.name"):
            assert_backend_conformance(_InvalidNameBackend(), case)


class TestNonLocalSarifFingerprintsAndUris:
    def test_sarif_preserves_remote_uris_and_isolates_asset_fingerprints(self) -> None:
        advisory = OsvAdvisory(
            id="PRECVE-2026-ABCDEF12",
            modified=PUBLISHED_AT,
            published=PUBLISHED_AT,
            summary="Requests SSRF",
            affected=(
                OsvAffected(
                    package=OsvPackage(ecosystem="PyPI", name="requests", purl="pkg:pypi/requests"),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(OsvRangeEvent(introduced="0"), OsvRangeEvent(fixed="2.31.0")),
                        ),
                    ),
                ),
            ),
        )

        # Two S3 objects sharing basename sbom.cdx.json + two EC2 instances in same region.
        s3_a = parse_sbom_bytes(
            _sample_cdx_bytes(version="2.30.0"),
            asset_id="s3://corp-sboms/team-a/sbom.cdx.json",
            backend="s3_sbom",
            location="s3://corp-sboms/team-a/sbom.cdx.json",
        )
        s3_b = parse_sbom_bytes(
            _sample_cdx_bytes(version="2.30.0"),
            asset_id="s3://corp-sboms/team-b/sbom.cdx.json",
            backend="s3_sbom",
            location="s3://corp-sboms/team-b/sbom.cdx.json",
        )
        ec2_1 = InventoryComponent(
            name="requests",
            version="2.30.0",
            purl="pkg:pypi/requests@2.30.0",
            canonical_purl="pkg:pypi/requests",
            ecosystem="pypi",
            asset=AssetRef(
                asset_id="arn:aws:ec2:us-east-1:123456789012:instance/i-1111",
                asset_type="AwsEc2Instance",
                backend="aws_security_hub",
                scope="123456789012",
                location="us-east-1",
            ),
        )
        ec2_2 = InventoryComponent(
            name="requests",
            version="2.30.0",
            purl="pkg:pypi/requests@2.30.0",
            canonical_purl="pkg:pypi/requests",
            ecosystem="pypi",
            asset=AssetRef(
                asset_id="arn:aws:ec2:us-east-1:123456789012:instance/i-2222",
                asset_type="AwsEc2Instance",
                backend="aws_security_hub",
                scope="123456789012",
                location="us-east-1",
            ),
        )
        oci_comp = parse_sbom_bytes(
            _sample_spdx_bytes(),
            asset_id="oci://ghcr.io/acme/api@sha256:deadbeef",
            backend="oci_sbom",
            location="oci://ghcr.io/acme/api@sha256:deadbeef",
        )[0]

        class _MultiAssetBackend:
            name = "aws_security_hub"

            def find_components(
                self, queries: Sequence[PackageQuery]
            ) -> tuple[InventoryComponent, ...]:
                del queries
                return (
                    *(c for c in (*s3_a, *s3_b) if c.canonical_purl == "pkg:pypi/requests"),
                    ec2_1,
                    ec2_2,
                    oci_comp,
                )

        from zerobom.backends import match_advisory_with_backend

        matches = match_advisory_with_backend(advisory, _MultiAssetBackend(), only_vulnerable=True)
        assert len(matches) == 5

        sarif = build_sarif_log((PipelineOutcome(osv=advisory, matches=matches),))
        results = sarif["runs"][0]["results"]
        assert len(results) == 5

        uris = [
            res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for res in results
        ]
        fingerprints = [res["partialFingerprints"]["primaryLocationLineHash"] for res in results]

        assert "corp-sboms/team-a/sbom.cdx.json" in uris
        assert "corp-sboms/team-b/sbom.cdx.json" in uris
        assert "ghcr.io/acme/api@sha256_deadbeef" in uris
        assert all(":" not in uri and "\\" not in uri for uri in uris)
        # All 5 assets produce distinct SARIF alert fingerprints.
        assert len(set(fingerprints)) == 5
        assert results[2]["properties"]["backend"] == "aws_security_hub"
        assert results[2]["properties"]["assetType"] == "AwsEc2Instance"

    def test_backend_load_error_hierarchy_preserves_backwards_compatibility(self) -> None:
        assert issubclass(BackendConfigError, BackendLoadError)
