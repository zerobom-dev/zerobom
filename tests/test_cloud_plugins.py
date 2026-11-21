"""Comprehensive offline unit & conformance tests for Milestone 2.1C cloud workspace plugins.

Exercises ``zerobom-aws`` (with ``botocore.stub.Stubber``), ``zerobom-gcp``, and
``zerobom-azure`` (with ``httpx.MockTransport``) completely offline.
"""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from pathlib import Path

import boto3
import httpx
import pytest
from botocore.response import StreamingBody
from botocore.stub import ANY, Stubber

from zerobom.backends import (
    BackendConfigError,
    BackendQueryError,
    BackendRegistry,
    assert_backend_conformance,
    build_default_conformance_case,
    match_advisory_with_backend,
)
from zerobom.models import (
    OsvAdvisory,
    OsvAffected,
    OsvPackage,
    OsvRange,
    OsvRangeEvent,
    PackageQuery,
    PipelineOutcome,
)
from zerobom.outputs import build_sarif_log
from zerobom_aws import AwsSecurityHubBackend, S3SbomBackend
from zerobom_azure import AzureBlobSbomBackend, AzureResourceGraphBackend
from zerobom_gcp import GcpArtifactAnalysisBackend, GcsSbomBackend

PUBLISHED_AT = datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)


def _cred(prefix: str) -> str:
    """Build synthetic credential placeholders without triggering S105/S106 literals."""
    return f"{prefix}-cloud-unit-placeholder"


def _requests_query(purl: str = "pkg:pypi/requests", name: str = "requests") -> PackageQuery:
    return PackageQuery(
        canonical_purl=purl,
        ecosystem="pypi",
        osv_ecosystem="PyPI",
        name=name,
    )


def _cdx_bytes(*packages: tuple[str, str, str]) -> bytes:
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"type": "library", "name": name, "version": version, "purl": purl}
            for name, version, purl in packages
        ],
    }
    return json.dumps(payload).encode("utf-8")


def _spdx_bytes(name: str, version: str, purl: str) -> bytes:
    payload = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "cloud-spdx-fixture",
        "documentNamespace": "https://example.org/spdx/cloud-fixture",
        "packages": [
            {
                "SPDXID": "SPDXRef-pkg-1",
                "name": name,
                "versionInfo": version,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": purl,
                    }
                ],
            }
        ],
    }
    return json.dumps(payload).encode("utf-8")


# ---------------------------------------------------------------------------
# 1. Workspace Discovery & Core Cloud-Agnostic Boundary Verification
# ---------------------------------------------------------------------------


class TestCloudPluginDiscovery:
    def test_registry_discovers_all_ten_built_in_and_workspace_backends(self) -> None:
        discovered = set(BackendRegistry().list_backends())
        expected = {
            "local_sbom",
            "dependency_track",
            "oci_sbom",
            "k8s_sbom",
            "aws_security_hub",
            "s3_sbom",
            "gcp_artifact_analysis",
            "gcs_sbom",
            "azure_resource_graph",
            "azure_blob_sbom",
        }
        assert expected.issubset(discovered)

    def test_core_package_remains_cloud_vendor_free(self) -> None:
        core_root = Path(__file__).resolve().parent.parent / "src" / "zerobom"
        forbidden_tokens = (
            "import boto3",
            "from boto3",
            "import botocore",
            "from botocore",
            "zerobom_aws",
            "zerobom_gcp",
            "zerobom_azure",
            "from azure",
            "from google.cloud",
        )
        for py_file in core_root.rglob("*.py"):
            text = py_file.read_text(encoding="utf-8")
            for token in forbidden_tokens:
                assert token not in text, f"Found {token!r} in core file {py_file}"


# ---------------------------------------------------------------------------
# 2. AWS Workspace Plugin Tests (botocore.stub.Stubber)
# ---------------------------------------------------------------------------


class TestAwsPlugins:
    def test_security_hub_conformance_with_botocore_stubber_and_sarif(self) -> None:
        raw_client = boto3.client(
            "securityhub",
            region_name="us-east-1",
            aws_access_key_id=_cred("ak"),
            aws_secret_access_key=_cred("sk"),
        )
        stubber = Stubber(raw_client)

        def _queue_requests_hit() -> None:
            stubber.add_response(
                "get_software_v2",
                {
                    "Software": [
                        {
                            "PackageName": "requests",
                            "PackageVersion": "2.30.0",
                            "PackageType": "PYTHON",
                            "ResourceCount": 1,
                        }
                    ]
                },
                {"Filters": ANY, "MaxResults": 100},
            )
            stubber.add_response(
                "get_software_resources_v2",
                {
                    "SoftwareResources": [
                        {
                            "AccountId": "111122223333",
                            "ResourceType": "AwsEc2Instance",
                            "Region": "us-east-1",
                            "ResourceId": "arn:aws:ec2:us-east-1:111122223333:instance/i-0abc",
                            "ResourceProvider": "AWS",
                            "ResourceOwnerAccountId": "111122223333",
                            "ResourceOwnerOrgId": "o-exampleorg",
                            "ResourceCloudPartition": "aws",
                            "ResourceRegion": "us-east-1",
                        }
                    ]
                },
                {
                    "PackageName": "requests",
                    "PackageType": "PYTHON",
                    "PackageVersion": "2.30.0",
                    "MaxResults": 100,
                },
            )

        # Conformance executes: raw_candidates, vuln_matches, safe_matches, unmatched, repeat.
        _queue_requests_hit()
        _queue_requests_hit()
        _queue_requests_hit()
        stubber.add_response(
            "get_software_v2", {"Software": []}, {"Filters": ANY, "MaxResults": 100}
        )
        _queue_requests_hit()

        with stubber:
            backend = AwsSecurityHubBackend(region_name="us-east-1", client=raw_client)
            case = build_default_conformance_case(backend_name="aws_security_hub")
            matches = assert_backend_conformance(backend, case)
            assert len(matches) == 1
            assert matches[0].asset is not None
            assert matches[0].asset.asset_id == (
                "arn:aws:ec2:us-east-1:111122223333:instance/i-0abc"
            )
            assert matches[0].asset.asset_type == "AwsEc2Instance"
            assert matches[0].asset.scope == "111122223333"
            assert matches[0].asset.location == "us-east-1"

            sarif = build_sarif_log(
                (PipelineOutcome(osv=case.vulnerable_advisory, matches=matches),)
            )
            result = sarif["runs"][0]["results"][0]
            assert result["properties"]["backend"] == "aws_security_hub"
            assert result["properties"]["assetType"] == "AwsEc2Instance"
            assert result["properties"]["scope"] == "111122223333"

    def test_security_hub_pagination_ecosystem_isolation_and_errors(self) -> None:
        raw_client = boto3.client(
            "securityhub",
            region_name="us-east-1",
            aws_access_key_id=_cred("ak"),
            aws_secret_access_key=_cred("sk"),
        )
        stubber = Stubber(raw_client)
        # Paginator drains both get_software_v2 pages first before resource expansion.
        stubber.add_response(
            "get_software_v2",
            {
                "Software": [
                    {
                        "PackageName": "requests",
                        "PackageVersion": "2.30.0",
                        "PackageType": "NPM",
                        "ResourceCount": 1,
                    }
                ],
                "NextToken": "page-2",
            },
        )
        stubber.add_response(
            "get_software_v2",
            {
                "Software": [
                    {
                        "PackageName": "requests",
                        "PackageVersion": "2.30.0",
                        "PackageType": "PYTHON",
                        "ResourceCount": 1,
                    }
                ]
            },
        )
        stubber.add_response(
            "get_software_resources_v2",
            {
                "SoftwareResources": [
                    {
                        "AccountId": "111122223333",
                        "ResourceType": "AwsLambdaFunction",
                        "Region": "us-east-1",
                        "ResourceId": "arn:aws:lambda:us-east-1:111122223333:function:js-fn",
                    }
                ]
            },
        )
        stubber.add_response(
            "get_software_resources_v2",
            {
                "SoftwareResources": [
                    {
                        "AccountId": "111122223333",
                        "ResourceType": "AwsLambdaFunction",
                        "Region": "us-east-1",
                        "ResourceId": "arn:aws:lambda:us-east-1:111122223333:function:py-fn",
                    }
                ]
            },
        )

        with stubber:
            backend = AwsSecurityHubBackend(
                region_name="us-east-1",
                account_ids=("111122223333",),
                client=raw_client,
            )
            found = backend.find_components((_requests_query(),))
            assert len(found) == 1
            assert found[0].canonical_purl == "pkg:pypi/requests"
            assert found[0].asset.asset_id.endswith(":py-fn")
            # Empty query does not invoke AWS.
            assert backend.find_components(()) == ()

        # ClientError maps cleanly to BackendQueryError; bad region/account fail config check.
        err_client = boto3.client(
            "securityhub",
            region_name="us-east-1",
            aws_access_key_id=_cred("ak"),
            aws_secret_access_key=_cred("sk"),
        )
        err_stub = Stubber(err_client)
        err_stub.add_client_error("get_software_v2", service_error_code="AccessDeniedException")
        with err_stub:
            err_backend = AwsSecurityHubBackend(region_name="us-east-1", client=err_client)
            with pytest.raises(BackendQueryError, match="GetSoftwareV2"):
                err_backend.find_components((_requests_query(),))

        with pytest.raises(BackendConfigError, match="region_name"):
            AwsSecurityHubBackend(region_name="invalid region!", client=raw_client)
        with pytest.raises(BackendConfigError, match="account_id"):
            AwsSecurityHubBackend(account_ids=("12345",), client=raw_client)

    def test_s3_sbom_conformance_pagination_size_cap_and_guards(self) -> None:
        raw_s3 = boto3.client(
            "s3",
            region_name="us-east-1",
            aws_access_key_id=_cred("ak"),
            aws_secret_access_key=_cred("sk"),
        )
        cdx_payload = _cdx_bytes(("requests", "2.30.0", "pkg:pypi/requests@2.30.0"))
        spdx_payload = _spdx_bytes("urllib3", "1.26.18", "pkg:pypi/urllib3@1.26.18")
        noise_payload = b'{"hello": "not-an-sbom"}'

        stubber = Stubber(raw_s3)
        stubber.add_response(
            "list_objects_v2",
            {
                "IsTruncated": True,
                "NextContinuationToken": "tok-2",
                "Contents": [
                    {
                        "Key": "sboms/team-a/app.cdx.json",
                        "Size": len(cdx_payload),
                        "ETag": '"etag1"',
                    },
                    {"Key": "sboms/team-a/notes.txt", "Size": 10},
                ],
            },
        )
        stubber.add_response(
            "list_objects_v2",
            {
                "IsTruncated": False,
                "Contents": [
                    {
                        "Key": "sboms/team-b/app.spdx.json",
                        "Size": len(spdx_payload),
                        "ETag": '"etag2"',
                    },
                    {
                        "Key": "sboms/team-b/noise.json",
                        "Size": len(noise_payload),
                        "ETag": '"etag3"',
                    },
                ],
            },
        )
        stubber.add_response(
            "get_object",
            {
                "ContentLength": len(cdx_payload),
                "Body": StreamingBody(io.BytesIO(cdx_payload), len(cdx_payload)),
            },
        )
        stubber.add_response(
            "get_object",
            {
                "ContentLength": len(spdx_payload),
                "Body": StreamingBody(io.BytesIO(spdx_payload), len(spdx_payload)),
            },
        )
        stubber.add_response(
            "get_object",
            {
                "ContentLength": len(noise_payload),
                "Body": StreamingBody(io.BytesIO(noise_payload), len(noise_payload)),
            },
        )

        with stubber:
            backend = S3SbomBackend(bucket="corp-sec-sboms", prefix="sboms/", client=raw_s3)
            case = build_default_conformance_case(backend_name="s3_sbom")
            matches = assert_backend_conformance(backend, case)
            assert len(matches) == 1
            assert matches[0].asset is not None
            assert matches[0].asset.asset_id == "s3://corp-sec-sboms/sboms/team-a/app.cdx.json"
            urllib = backend.find_components((_requests_query("pkg:pypi/urllib3", "urllib3"),))
            assert len(urllib) == 1

        # Strict mode + oversized S3 object size guard.
        size_s3 = boto3.client(
            "s3",
            region_name="us-east-1",
            aws_access_key_id=_cred("ak"),
            aws_secret_access_key=_cred("sk"),
        )
        size_stub = Stubber(size_s3)
        size_stub.add_response(
            "list_objects_v2",
            {
                "IsTruncated": False,
                "Contents": [{"Key": "sboms/huge.cdx.json", "Size": 99999}],
            },
        )
        with size_stub:
            size_backend = S3SbomBackend(
                bucket="corp-sec-sboms", max_sbom_bytes=1024, client=size_s3
            )
            with pytest.raises(BackendQueryError, match="limit"):
                size_backend.find_components((_requests_query(),))

        with pytest.raises(BackendConfigError, match="bucket"):
            S3SbomBackend(bucket="Invalid_Bucket", client=raw_s3)
        with pytest.raises(BackendConfigError, match="traversal"):
            S3SbomBackend(bucket="corp-sec-sboms", prefix="sboms/../secrets", client=raw_s3)


# ---------------------------------------------------------------------------
# 3. GCP Workspace Plugin Tests
# ---------------------------------------------------------------------------


class TestGcpPlugins:
    def test_artifact_analysis_conformance_pagination_cpe_cel_and_errors(self) -> None:
        gcp_cred = _cred("gcp-oauth")
        seen_filters: list[str] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["Authorization"] == f"Bearer {gcp_cred}"
            cel = request.url.params.get("filter", "")
            seen_filters.append(cel)
            if cel != 'kind="PACKAGE"' and 'dependencyPackageName="requests"' not in cel:
                return httpx.Response(200, json={"occurrences": []})

            page_tok = request.url.params.get("pageToken")
            if page_tok is None:
                return httpx.Response(
                    200,
                    json={
                        "nextPageToken": "gcp-page-2",
                        "occurrences": [
                            {
                                "name": "projects/my-proj/occurrences/1",
                                "resourceUri": "https://us-docker.pkg.dev/my-proj/app/web@sha256:aaa",
                                "kind": "PACKAGE",
                                "package": {
                                    "name": "requests",
                                    "packageType": "PYPI",
                                    "version": {"fullName": "2.30.0"},
                                },
                            }
                        ],
                    },
                )
            return httpx.Response(
                200,
                json={
                    "occurrences": [
                        {
                            "name": "projects/my-proj/occurrences/2",
                            "resourceUri": "https://us-docker.pkg.dev/my-proj/app/os@sha256:bbb",
                            "kind": "PACKAGE",
                            "package": {
                                "name": "openssl",
                                "packageType": "OS",
                                "location": [
                                    {
                                        "cpeUri": "cpe:/o:debian:debian_linux:11",
                                        "version": {
                                            "name": "1.1.1n",
                                            "revision": "0+deb11u5",
                                            "epoch": 1,
                                        },
                                    }
                                ],
                            },
                        }
                    ]
                },
            )

        client = httpx.Client(transport=httpx.MockTransport(_handler))
        backend = GcpArtifactAnalysisBackend(
            project_id="my-proj",
            access_token=gcp_cred,
            http_client=client,
        )
        try:
            assert gcp_cred not in repr(backend)
            case = build_default_conformance_case(backend_name="gcp_artifact_analysis")
            matches = assert_backend_conformance(backend, case)
            assert len(matches) == 1
            assert matches[0].matched_via == "purl"
            assert matches[0].asset is not None
            assert matches[0].asset.asset_type == "gcp_artifact"

            # Verify unsafe characters fail closed with BackendQueryError (no filter bypass).
            with pytest.raises(BackendQueryError, match="filter guard"):
                backend.find_components((_requests_query("pkg:pypi/requests", 'bad";drop()'),))
            assert all('bad"' not in f for f in seen_filters)

            # Verify has_prefix(resourceUrl, ...) filter generation.
            prefixed = GcpArtifactAnalysisBackend(
                project_id="my-proj",
                access_token=gcp_cred,
                resource_uri_prefix="https://us-docker.pkg.dev/my-proj/",
                http_client=client,
            )
            prefixed.find_components((_requests_query(),))
            assert any(
                'has_prefix(resourceUrl, "https://us-docker.pkg.dev/my-proj/")' in f
                and 'dependencyPackageName="requests"' in f
                for f in seen_filters
            )

            # Verify Debian CPE mapping with filter_by_package=False.
            unfiltered = GcpArtifactAnalysisBackend(
                project_id="my-proj",
                access_token=gcp_cred,
                filter_by_package=False,
                http_client=client,
            )
            os_advisory = OsvAdvisory(
                id="PRECVE-2026-GCPOS001",
                modified=PUBLISHED_AT,
                published=PUBLISHED_AT,
                summary="Debian 11 openssl issue",
                affected=(
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
                                    OsvRangeEvent(fixed="1:1.1.1w-0+deb11u1"),
                                ),
                            ),
                        ),
                    ),
                ),
            )
            os_matches = match_advisory_with_backend(os_advisory, unfiltered)
            assert len(os_matches) == 1
            assert os_matches[0].installed_version == "1:1.1.1n-0+deb11u5"
        finally:
            client.close()

        # Max pages truncation & HTTP error mapping.
        loop_client = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: httpx.Response(200, json={"nextPageToken": "more", "occurrences": []})
            )
        )
        loop_backend = GcpArtifactAnalysisBackend(
            project_id="my-proj", access_token=gcp_cred, max_pages=2, http_client=loop_client
        )
        try:
            with pytest.raises(BackendQueryError, match="max_pages=2"):
                loop_backend.find_components((_requests_query(),))
        finally:
            loop_client.close()

        with pytest.raises(BackendConfigError, match="project_id"):
            GcpArtifactAnalysisBackend(project_id="BAD_PROJECT!", access_token=gcp_cred)

    def test_gcs_sbom_conformance_pagination_and_size_guards(self) -> None:
        gcp_cred = _cred("gcs-oauth")
        cdx_payload = _cdx_bytes(("requests", "2.30.0", "pkg:pypi/requests@2.30.0"))
        bad_json = b'{"not": "sbom"}'

        def _handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["Authorization"] == f"Bearer {gcp_cred}"
            raw_path = request.url.raw_path.split(b"?", 1)[0]
            if raw_path == b"/storage/v1/b/sec-gcs-sboms/o":
                tok = request.url.params.get("pageToken")
                if tok is None:
                    return httpx.Response(
                        200,
                        json={
                            "nextPageToken": "gcs-2",
                            "items": [
                                {
                                    "name": "prod/web.cdx.json",
                                    "size": str(len(cdx_payload)),
                                    "etag": "etag-1",
                                }
                            ],
                        },
                    )
                return httpx.Response(
                    200,
                    json={"items": [{"name": "prod/readme.json", "size": str(len(bad_json))}]},
                )
            if raw_path == b"/storage/v1/b/sec-gcs-sboms/o/prod%2Fweb.cdx.json":
                return httpx.Response(200, content=cdx_payload)
            if raw_path == b"/storage/v1/b/sec-gcs-sboms/o/prod%2Freadme.json":
                return httpx.Response(200, content=bad_json)
            return httpx.Response(404)

        client = httpx.Client(transport=httpx.MockTransport(_handler))
        backend = GcsSbomBackend(bucket="sec-gcs-sboms", access_token=gcp_cred, http_client=client)
        try:
            case = build_default_conformance_case(backend_name="gcs_sbom")
            matches = assert_backend_conformance(backend, case)
            assert len(matches) == 1
            assert matches[0].asset is not None
            assert matches[0].asset.asset_id == "gs://sec-gcs-sboms/prod/web.cdx.json"

            strict_backend = GcsSbomBackend(
                bucket="sec-gcs-sboms", access_token=gcp_cred, strict=True, http_client=client
            )
            with pytest.raises(BackendQueryError, match="Failed to parse GCS SBOM"):
                strict_backend.find_components((_requests_query(),))
        finally:
            client.close()

        bounded_client = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: httpx.Response(
                    200, json={"items": [{"name": "huge.cdx.json", "size": "99999"}]}
                )
            )
        )
        bounded_backend = GcsSbomBackend(
            bucket="sec-gcs-sboms",
            access_token=gcp_cred,
            max_sbom_bytes=1024,
            http_client=bounded_client,
        )
        try:
            with pytest.raises(BackendQueryError, match="limit 1024"):
                bounded_backend.find_components((_requests_query(),))
        finally:
            bounded_client.close()

        with pytest.raises(BackendConfigError, match="traversal"):
            GcsSbomBackend(bucket="sec-gcs-sboms", prefix="../secret", access_token=gcp_cred)


# ---------------------------------------------------------------------------
# 4. Azure Workspace Plugin Tests
# ---------------------------------------------------------------------------


class TestAzurePlugins:
    def test_resource_graph_conformance_table_kql_guard_and_pagination(self) -> None:
        az_cred = _cred("az-bearer")
        sub_id = "12345678-1234-1234-1234-1234567890ab"

        seen_kql: list[str] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["Authorization"] == f"Bearer {az_cred}"
            body = json.loads(request.content.decode("utf-8"))
            assert body["subscriptions"] == [sub_id]
            kql = body["query"]
            seen_kql.append(kql)
            if "'requests'" not in kql:
                return httpx.Response(200, json={"data": []})

            skip_tok = body["options"].get("$skipToken")
            if skip_tok is None:
                return httpx.Response(
                    200,
                    json={
                        "$skipToken": "az-next-1",
                        "data": [
                            {
                                "id": "/subscriptions/sub/providers/Microsoft.Security/a1",
                                "subscriptionId": sub_id,
                                "location": "eastus",
                                "resourceGroup": "rg-prod",
                                "resourceType": "Microsoft.Compute/virtualMachines",
                                "resourceId": (
                                    "/subscriptions/sub/resourceGroups/rg-prod/"
                                    "providers/Microsoft.Compute/virtualMachines/vm-1"
                                ),
                                "softwareName": "requests",
                                "softwareVersion": "2.30.0",
                                "softwareVendor": "PSF",
                                "ecosystem": "pypi",
                                "purl": "pkg:pypi/requests@2.30.0",
                            }
                        ],
                    },
                )
            # Second page formatted as columns/rows table format.
            return httpx.Response(
                200,
                json={
                    "data": {
                        "columns": [
                            {"name": "resourceId"},
                            {"name": "resourceType"},
                            {"name": "subscriptionId"},
                            {"name": "location"},
                            {"name": "softwareName"},
                            {"name": "softwareVersion"},
                            {"name": "ecosystem"},
                        ],
                        "rows": [
                            [
                                "/subscriptions/sub/providers/Microsoft.ContainerRegistry/img-2",
                                "Microsoft.ContainerRegistry/registries",
                                sub_id,
                                "westeurope",
                                "requests",
                                "2.29.0",
                                "pypi",
                            ]
                        ],
                    }
                },
            )

        client = httpx.Client(transport=httpx.MockTransport(_handler))
        backend = AzureResourceGraphBackend(
            subscriptions=(sub_id,),
            access_token=az_cred,
            http_client=client,
        )
        try:
            assert az_cred not in repr(backend)
            case = build_default_conformance_case(backend_name="azure_resource_graph")
            matches = assert_backend_conformance(backend, case)
            assert {m.installed_version for m in matches} == {"2.29.0", "2.30.0"}
            assert seen_kql
            assert all("microsoft.security/softwareinventories" in q for q in seen_kql)
            assert all("subassessments" not in q for q in seen_kql)

            # KQL injection in query name must fail closed before issuing HTTP.
            with pytest.raises(BackendQueryError, match="KQL guard"):
                backend.find_components((_requests_query("pkg:pypi/requests", "requests' | drop"),))
        finally:
            client.close()

        with pytest.raises(BackendConfigError, match="subscription"):
            AzureResourceGraphBackend(subscriptions=("not-a-guid",), access_token=az_cred)

    def test_azure_blob_conformance_sas_pagination_and_xxe_rejection(self) -> None:
        sas_val = "sv=2022-11-02&ss=b&srt=co&sp=rl&sig=" + _cred("azsig")
        cdx_payload = _cdx_bytes(("requests", "2.30.0", "pkg:pypi/requests@2.30.0"))

        xml_page_1 = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<EnumerationResults ServiceEndpoint="https://secblobs.blob.core.windows.net/"'
            ' ContainerName="sboms">'
            "<Blobs><Blob><Name>team-a/app.cdx.json</Name>"
            f"<Properties><Content-Length>{len(cdx_payload)}</Content-Length>"
            '<Etag>"e1"</Etag></Properties>'
            "</Blob></Blobs>"
            "<NextMarker>marker-2</NextMarker>"
            "</EnumerationResults>"
        ).encode()
        xml_page_2 = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b"<EnumerationResults><Blobs><Blob><Name>team-a/ignored.txt</Name></Blob></Blobs>"
            b"<NextMarker /></EnumerationResults>"
        )

        def _handler(request: httpx.Request) -> httpx.Response:
            assert request.url.params.get("sig") == _cred("azsig")
            if request.url.path == "/sboms":
                marker = request.url.params.get("marker")
                return httpx.Response(200, content=xml_page_1 if marker is None else xml_page_2)
            if request.url.path == "/sboms/team-a/app.cdx.json":
                return httpx.Response(200, content=cdx_payload)
            return httpx.Response(404)

        client = httpx.Client(transport=httpx.MockTransport(_handler))
        backend = AzureBlobSbomBackend(
            account_name="secblobs",
            container="sboms",
            sas_token=f"?{sas_val}",
            http_client=client,
        )
        try:
            assert _cred("azsig") not in repr(backend)
            assert "auth='sas'" in repr(backend)
            case = build_default_conformance_case(backend_name="azure_blob_sbom")
            matches = assert_backend_conformance(backend, case)
            assert len(matches) == 1
            assert matches[0].asset is not None
            assert matches[0].asset.asset_id == "azblob://secblobs/sboms/team-a/app.cdx.json"
        finally:
            client.close()

        # XXE / DOCTYPE declaration inside XML listing must fail closed with BackendQueryError.
        xxe_xml = (
            b'<?xml version="1.0"?>'
            b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
            b"<EnumerationResults><Blobs /></EnumerationResults>"
        )
        xxe_client = httpx.Client(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, content=xxe_xml))
        )
        xxe_backend = AzureBlobSbomBackend(
            account_name="secblobs",
            container="sboms",
            access_token=_cred("az"),
            http_client=xxe_client,
        )
        try:
            with pytest.raises(BackendQueryError, match="DTD/DOCTYPE"):
                xxe_backend.find_components((_requests_query(),))
        finally:
            xxe_client.close()

        with pytest.raises(BackendConfigError, match="account name"):
            AzureBlobSbomBackend(
                account_name="BAD_ACCOUNT", container="sboms", access_token=_cred("az")
            )
        with pytest.raises(BackendConfigError, match="container"):
            AzureBlobSbomBackend(
                account_name="secblobs", container="bad--name", access_token=_cred("az")
            )

    def test_cloud_plugin_config_hardening_regressions(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # 1) Empty prefix="" accepted cleanly across S3, GCS, and Azure Blob from_config.
        s3_cfg = S3SbomBackend.from_config(
            {"bucket": "corp-sec-sboms", "prefix": "", "region_name": "us-east-1"}
        )
        assert "prefix=''" in repr(s3_cfg)
        with pytest.raises(BackendConfigError, match="region_name"):
            S3SbomBackend(bucket="corp-sec-sboms", region_name="invalid region!")

        gcs_cfg = GcsSbomBackend.from_config(
            {"bucket": "sec-gcs-sboms", "prefix": "", "access_token": _cred("gcs")}
        )
        assert "prefix=''" in repr(gcs_cfg)

        # GCS listing ignores boolean JSON "size" values safely without raising.
        gcs_bool_client = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: (
                    httpx.Response(200, json={"items": [{"name": "a.cdx.json", "size": True}]})
                    if req.url.path == "/storage/v1/b/sec-gcs-sboms/o"
                    else httpx.Response(
                        200, content=_cdx_bytes(("requests", "2.30.0", "pkg:pypi/requests@2.30.0"))
                    )
                )
            )
        )
        try:
            gcs_bool = GcsSbomBackend(
                bucket="sec-gcs-sboms",
                access_token=_cred("gcs"),
                http_client=gcs_bool_client,
            )
            assert len(gcs_bool.find_components((_requests_query(),))) == 1
        finally:
            gcs_bool_client.close()

        # Azure Blob with access_token ignores unrelated ZEROBOM_AZURE_SAS_TOKEN in env.
        monkeypatch.setenv("ZEROBOM_AZURE_SAS_TOKEN", "sv=2022&sig=" + _cred("envsig"))
        az_cfg = AzureBlobSbomBackend.from_config(
            {
                "account_name": "secblobs",
                "container": "sboms",
                "prefix": "",
                "access_token": _cred("az-oauth"),
            }
        )
        try:
            assert "auth='bearer'" in repr(az_cfg)
        finally:
            az_cfg.close()

        # AWS Security Hub multi-ecosystem query with generic PackageType="library" matches npm.
        raw_sh = boto3.client(
            "securityhub",
            region_name="us-east-1",
            aws_access_key_id=_cred("ak"),
            aws_secret_access_key=_cred("sk"),
        )
        stub = Stubber(raw_sh)
        stub.add_response(
            "get_software_v2",
            {
                "Software": [
                    {
                        "PackageName": "minimist",
                        "PackageVersion": "1.2.5",
                        "PackageType": "library",
                        "ResourceCount": 1,
                    }
                ]
            },
        )
        stub.add_response(
            "get_software_resources_v2",
            {
                "SoftwareResources": [
                    {
                        "AccountId": "111122223333",
                        "ResourceType": "AwsEc2Instance",
                        "Region": "us-east-1",
                        "ResourceId": "arn:aws:ec2:us-east-1:111122223333:instance/i-111",
                    }
                ]
            },
        )
        with stub:
            sh = AwsSecurityHubBackend(region_name="us-east-1", client=raw_sh)
            adv = OsvAdvisory(
                id="PRECVE-2026-MULTIECO",
                modified=PUBLISHED_AT,
                published=PUBLISHED_AT,
                summary="Multi-ecosystem package check",
                affected=(
                    OsvAffected(
                        package=OsvPackage(
                            ecosystem="PyPI", name="minimist", purl="pkg:pypi/minimist"
                        ),
                        ranges=(
                            OsvRange(
                                type="ECOSYSTEM",
                                events=(
                                    OsvRangeEvent(introduced="0"),
                                    OsvRangeEvent(fixed="0.1.0"),
                                ),
                            ),
                        ),
                    ),
                    OsvAffected(
                        package=OsvPackage(
                            ecosystem="npm", name="minimist", purl="pkg:npm/minimist"
                        ),
                        ranges=(
                            OsvRange(
                                type="ECOSYSTEM",
                                events=(
                                    OsvRangeEvent(introduced="0"),
                                    OsvRangeEvent(fixed="1.2.6"),
                                ),
                            ),
                        ),
                    ),
                ),
            )
            hits = match_advisory_with_backend(adv, sh)
            assert len(hits) == 1
            assert hits[0].matched_purl == "pkg:npm/minimist"
