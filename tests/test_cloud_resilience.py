"""Comprehensive offline resilience, schema, auth-refresh, and error-path tests."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
from datetime import UTC, datetime, timedelta
from typing import Any

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
)
from zerobom_aws import AwsInspectorSbomBackend, AwsSecurityHubBackend, S3SbomBackend
from zerobom_aws._session import build_refreshable_assume_role_credentials
from zerobom_azure import AzureBlobSbomBackend, AzureResourceGraphBackend
from zerobom_azure._auth import AzureTokenProvider
from zerobom_gcp import GcpArtifactAnalysisBackend, GcsSbomBackend
from zerobom_gcp._auth import GcpTokenProvider

PUBLISHED_AT = datetime(2026, 11, 20, 12, 0, 0, tzinfo=UTC)


def _cred(prefix: str) -> str:
    """Construct synthetic credential placeholder without triggering secret scanners."""
    return f"{prefix}-resilience-placeholder"


def _query(
    purl: str = "pkg:pypi/requests",
    name: str = "requests",
    eco: str = "pypi",
    osv_eco: str = "PyPI",
) -> PackageQuery:
    return PackageQuery(
        canonical_purl=purl,
        ecosystem=eco,
        osv_ecosystem=osv_eco,
        name=name,
    )


def _cdx_bytes(
    *packages: tuple[str, str, str],
    properties: list[dict[str, str]] | None = None,
) -> bytes:
    payload: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {"type": "library", "name": name, "version": version, "purl": purl}
            for name, version, purl in packages
        ],
    }
    if properties is not None:
        payload["metadata"] = {
            "component": {
                "type": "container",
                "name": "arn:aws:ecr:us-east-1:111122223333:repository/web",
            },
            "properties": properties,
        }
    return json.dumps(payload).encode("utf-8")


# ---------------------------------------------------------------------------
# AWS Resilience & New Features (Inspector2, Org Scopes, STS, Gzip, Glacier)
# ---------------------------------------------------------------------------


class TestAwsResilienceAndInspector2:
    def test_inspector2_readonly_polling_conformance_and_enrichment(self) -> None:
        raw_insp = boto3.client(
            "inspector2",
            region_name="us-east-1",
            aws_access_key_id=_cred("ak"),
            aws_secret_access_key=_cred("sk"),
        )
        raw_s3 = boto3.client(
            "s3",
            region_name="us-east-1",
            aws_access_key_id=_cred("ak"),
            aws_secret_access_key=_cred("sk"),
        )
        cdx_gz = gzip.compress(
            _cdx_bytes(
                ("requests", "2.30.0", "pkg:pypi/requests@2.30.0"),
                properties=[
                    {
                        "name": "amazon:inspector:sbom_generator:resource_id",
                        "value": "arn:aws:ec2:us-east-1:111122223333:instance/i-insp01",
                    },
                    {
                        "name": "amazon:inspector:sbom_generator:resource_type",
                        "value": "AWS_EC2_INSTANCE",
                    },
                    {"name": "amazon:inspector:sbom_generator:account_id", "value": "111122223333"},
                    {"name": "amazon:inspector:sbom_generator:region", "value": "us-east-1"},
                ],
            )
        )

        insp_stub = Stubber(raw_insp)
        s3_stub = Stubber(raw_s3)
        insp_stub.add_response(
            "get_sbom_export",
            {"reportId": "rep-1234", "status": "IN_PROGRESS"},
            {"reportId": "rep-1234"},
        )
        insp_stub.add_response(
            "get_sbom_export",
            {
                "reportId": "rep-1234",
                "status": "SUCCEEDED",
                "format": "CYCLONEDX_1_4",
                "s3Destination": {
                    "bucketName": "insp-exports",
                    "keyPrefix": "exports/rep-1234/",
                    "kmsKeyArn": (
                        "arn:aws:kms:us-east-1:111122223333:key/"
                        "12345678-1234-1234-1234-1234567890ab"
                    ),
                },
            },
            {"reportId": "rep-1234"},
        )
        s3_stub.add_response(
            "list_objects_v2",
            {
                "IsTruncated": False,
                "Contents": [{"Key": "exports/rep-1234/ec2.cdx.json.gz", "Size": len(cdx_gz)}],
            },
            {"Bucket": "insp-exports", "Prefix": "exports/rep-1234/"},
        )
        s3_stub.add_response(
            "get_object",
            {
                "ContentLength": len(cdx_gz),
                "ContentEncoding": "gzip",
                "Body": StreamingBody(io.BytesIO(cdx_gz), len(cdx_gz)),
            },
            {"Bucket": "insp-exports", "Key": "exports/rep-1234/ec2.cdx.json.gz"},
        )

        sleeps: list[float] = []
        clock = [0.0]

        def _fake_sleep(secs: float) -> None:
            sleeps.append(secs)
            clock[0] += secs

        with insp_stub, s3_stub:
            backend = AwsInspectorSbomBackend(
                report_id="rep-1234",
                region_name="us-east-1",
                poll_interval_seconds=2.0,
                max_concurrency=1,
                inspector_client=raw_insp,
                s3_client=raw_s3,
                sleep_fn=_fake_sleep,
                monotonic_fn=lambda: clock[0],
            )
            case = build_default_conformance_case(backend_name="aws_inspector_sbom")
            # Conformance caches index after load(), so 2 Stubber calls suffice across 5 queries.
            matches = assert_backend_conformance(backend, case)
            assert len(matches) == 1
            assert sleeps == [2.0]
            assert matches[0].asset is not None
            assert (
                matches[0].asset.asset_id == "arn:aws:ec2:us-east-1:111122223333:instance/i-insp01"
            )
            assert matches[0].asset.asset_type == "AWS_EC2_INSTANCE"
            assert matches[0].asset.scope == "111122223333"
            assert matches[0].asset.location == "us-east-1"

    def test_inspector2_trigger_export_no_findings_and_failures(self) -> None:
        raw_insp = boto3.client(
            "inspector2",
            region_name="us-east-1",
            aws_access_key_id=_cred("ak"),
            aws_secret_access_key=_cred("sk"),
        )
        raw_s3 = boto3.client(
            "s3",
            region_name="us-east-1",
            aws_access_key_id=_cred("ak"),
            aws_secret_access_key=_cred("sk"),
        )
        cdx_raw = _cdx_bytes(("requests", "2.30.0", "pkg:pypi/requests@2.30.0"))
        kms_arn = "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-1234567890ab"

        insp_stub = Stubber(raw_insp)
        s3_stub = Stubber(raw_s3)
        insp_stub.add_response(
            "create_sbom_export",
            {"reportId": "rep-new-1"},
            {
                "reportFormat": "SPDX_2_3",
                "s3Destination": {
                    "bucketName": "insp-out",
                    "keyPrefix": "daily/",
                    "kmsKeyArn": kms_arn,
                    "expectedBucketOwner": "111122223333",
                },
                "resourceFilterCriteria": {
                    "accountId": [{"comparison": "EQUALS", "value": "111122223333"}],
                    "resourceType": [{"comparison": "EQUALS", "value": "AWS_ECR_CONTAINER_IMAGE"}],
                },
            },
        )
        insp_stub.add_response(
            "get_sbom_export",
            {
                "reportId": "rep-new-1",
                "status": "SUCCEEDED",
                "s3Destination": {
                    "bucketName": "insp-out",
                    "keyPrefix": "daily/",
                    "kmsKeyArn": kms_arn,
                },
            },
            {"reportId": "rep-new-1"},
        )
        s3_stub.add_response(
            "list_objects_v2",
            {
                "IsTruncated": False,
                "Contents": [{"Key": "daily/ecr.spdx.json", "Size": len(cdx_raw)}],
            },
        )
        s3_stub.add_response(
            "get_object",
            {
                "ContentLength": len(cdx_raw),
                "Body": StreamingBody(io.BytesIO(cdx_raw), len(cdx_raw)),
            },
        )

        with insp_stub, s3_stub:
            backend = AwsInspectorSbomBackend.from_config(
                {
                    "trigger_export": True,
                    "s3_bucket": "insp-out",
                    "s3_prefix": "daily/",
                    "kms_key_arn": kms_arn,
                    "expected_bucket_owner": "111122223333",
                    "report_format": "SPDX_2_3",
                    "account_ids": ["111122223333"],
                    "resource_types": ["AWS_ECR_CONTAINER_IMAGE"],
                    "region_name": "us-east-1",
                }
            )
            # Replace clients cleanly for offline Stubber execution.
            backend._inspector_client = raw_insp
            backend._s3_client = raw_s3
            assert backend.load() == 1
            assert len(backend.find_components((_query(),))) == 1

        # NO_FINDINGS_FOUND returns empty inventory (0) without crashing.
        empty_insp = boto3.client(
            "inspector2",
            region_name="us-east-1",
            aws_access_key_id=_cred("ak"),
            aws_secret_access_key=_cred("sk"),
        )
        empty_stub = Stubber(empty_insp)
        empty_stub.add_response(
            "get_sbom_export",
            {"reportId": "rep-empty", "status": "FAILED", "errorCode": "NO_FINDINGS_FOUND"},
        )
        with empty_stub:
            empty_backend = AwsInspectorSbomBackend(
                report_id="rep-empty",
                region_name="us-east-1",
                inspector_client=empty_insp,
                s3_client=raw_s3,
            )
            assert empty_backend.find_components((_query(),)) == ()

        # Poll timeout + FAILED error codes fail closed.
        fail_insp = boto3.client(
            "inspector2",
            region_name="us-east-1",
            aws_access_key_id=_cred("ak"),
            aws_secret_access_key=_cred("sk"),
        )
        fail_stub = Stubber(fail_insp)
        fail_stub.add_response(
            "get_sbom_export",
            {
                "reportId": "rep-fail",
                "status": "FAILED",
                "errorCode": "INVALID_PERMISSIONS",
                "errorMessage": "Missing KMS permission",
            },
        )
        with fail_stub:
            fail_backend = AwsInspectorSbomBackend(
                report_id="rep-fail",
                region_name="us-east-1",
                inspector_client=fail_insp,
                s3_client=raw_s3,
            )
            with pytest.raises(BackendQueryError, match="INVALID_PERMISSIONS"):
                fail_backend.load()

        with pytest.raises(BackendConfigError, match="either 'report_id'"):
            AwsInspectorSbomBackend(
                region_name="us-east-1", inspector_client=raw_insp, s3_client=raw_s3
            )
        with pytest.raises(BackendConfigError, match="not both"):
            AwsInspectorSbomBackend(
                report_id="rep-1234",
                trigger_export=True,
                s3_bucket="b",
                inspector_client=raw_insp,
                s3_client=raw_s3,
            )
        assert "aws_inspector_sbom" in BackendRegistry().list_backends()

    def test_security_hub_org_scopes_sts_assume_role_and_guardrails(self) -> None:
        raw_sh = boto3.client(
            "securityhub",
            region_name="us-east-1",
            aws_access_key_id=_cred("ak"),
            aws_secret_access_key=_cred("sk"),
        )
        stub = Stubber(raw_sh)
        expected_scopes = {
            "AwsOrganizations": [
                {"OrganizationId": "o-abcdefghij"},
                {"OrganizationalUnitId": "ou-abcd-12345678"},
            ]
        }
        stub.add_response(
            "get_software_v2",
            {
                "Software": [
                    # Missing PackageType should be skipped without fabricating "library".
                    {
                        "PackageName": "requests_broken",
                        "PackageVersion": "1.0",
                        "PackageType": "",
                        "ResourceCount": 1,
                    },
                    {
                        "PackageName": "requests_alt",
                        "PackageVersion": "2.30.0",
                        "PackageType": "PYTHON",
                        "ResourceCount": 1,
                    },
                ]
            },
            {"Filters": ANY, "Scopes": expected_scopes, "MaxResults": 100},
        )
        stub.add_response(
            "get_software_resources_v2",
            {
                "SoftwareResources": [
                    {
                        "AccountId": "111122223333",
                        "ResourceType": "AwsEc2Instance",
                        "Region": "us-east-1",
                        "ResourceId": "arn:aws:ec2:us-east-1:111122223333:instance/i-org",
                    }
                ]
            },
            {
                "PackageName": "requests_alt",
                "PackageType": "PYTHON",
                "PackageVersion": "2.30.0",
                "Scopes": expected_scopes,
                "MaxResults": 100,
            },
        )
        stub.add_response(
            "get_software_v2",
            {"Software": []},
            {"Filters": ANY, "Scopes": expected_scopes, "MaxResults": 100},
        )

        with stub:
            sh = AwsSecurityHubBackend(
                region_name="us-east-1",
                organization_id="o-abcdefghij",
                organizational_unit_ids=("ou-abcd-12345678",),
                client=raw_sh,
            )
            found = sh.find_components((_query("pkg:pypi/requests-alt", "requests-alt"),))
            assert len(found) == 1
            assert found[0].canonical_purl == "pkg:pypi/requests-alt"

        # Old client lacking GetSoftwareV2 fails closed with upgrade guidance.
        with pytest.raises(BackendConfigError, match=r"boto3/botocore >= 1\.44\.0"):
            AwsSecurityHubBackend(region_name="us-east-1", client=object())

        # Refreshable STS AssumeRole credentials via Stubber.
        sts_client = boto3.client(
            "sts",
            region_name="us-east-1",
            aws_access_key_id=_cred("ak"),
            aws_secret_access_key=_cred("sk"),
        )
        sts_stub = Stubber(sts_client)
        exp1 = datetime.now(UTC) - timedelta(seconds=10)
        exp2 = datetime.now(UTC) + timedelta(hours=1)
        sts_stub.add_response(
            "assume_role",
            {
                "Credentials": {
                    "AccessKeyId": "ASIA1111111111111111",
                    "SecretAccessKey": _cred("sts-sec-1"),
                    "SessionToken": _cred("sts-tok-1"),
                    "Expiration": exp1,
                }
            },
            {
                "RoleArn": "arn:aws:iam::111122223333:role/ZeroBomReadOnly",
                "RoleSessionName": "zerobom-test",
                "ExternalId": "ext-123",
            },
        )
        sts_stub.add_response(
            "assume_role",
            {
                "Credentials": {
                    "AccessKeyId": "ASIA2222222222222222",
                    "SecretAccessKey": _cred("sts-sec-2"),
                    "SessionToken": _cred("sts-tok-2"),
                    "Expiration": exp2,
                }
            },
        )
        with sts_stub:
            creds = build_refreshable_assume_role_credentials(
                role_arn="arn:aws:iam::111122223333:role/ZeroBomReadOnly",
                external_id="ext-123",
                role_session_name="zerobom-test",
                sts_client=sts_client,
            )
            frozen = creds.get_frozen_credentials()
            assert frozen.access_key == "ASIA2222222222222222"

    def test_s3_gzip_bomb_glacier_skip_and_concurrent_determinism(self) -> None:
        # 1) Glacier/DEEP_ARCHIVE skipped cleanly while GLACIER_IR & gzip are loaded.
        raw_s3 = boto3.client(
            "s3",
            region_name="us-east-1",
            aws_access_key_id=_cred("ak"),
            aws_secret_access_key=_cred("sk"),
        )
        cdx_gz = gzip.compress(_cdx_bytes(("requests", "2.30.0", "pkg:pypi/requests@2.30.0")))
        stub = Stubber(raw_s3)
        stub.add_response(
            "list_objects_v2",
            {
                "IsTruncated": False,
                "Contents": [
                    {"Key": "old/glacier.cdx.json", "Size": 100, "StorageClass": "GLACIER"},
                    {"Key": "old/deep.cdx.json", "Size": 100, "StorageClass": "DEEP_ARCHIVE"},
                    {
                        "Key": "active/app.cdx.json.gz",
                        "Size": len(cdx_gz),
                        "StorageClass": "GLACIER_IR",
                    },
                ],
            },
            {"Bucket": "corp-sboms", "Prefix": "", "ExpectedBucketOwner": "111122223333"},
        )
        stub.add_response(
            "get_object",
            {
                "ContentLength": len(cdx_gz),
                "ContentEncoding": "gzip",
                "Body": StreamingBody(io.BytesIO(cdx_gz), len(cdx_gz)),
            },
            {
                "Bucket": "corp-sboms",
                "Key": "active/app.cdx.json.gz",
                "ExpectedBucketOwner": "111122223333",
            },
        )
        with stub:
            s3 = S3SbomBackend(
                bucket="corp-sboms",
                expected_bucket_owner="111122223333",
                max_concurrency=1,
                client=raw_s3,
            )
            case = build_default_conformance_case(backend_name="s3_sbom")
            assert len(assert_backend_conformance(s3, case)) == 1

        # 2) Gzip bomb caught before unbounded memory allocation.
        bomb_gz = gzip.compress(b'{"bomFormat":"CycloneDX","pad":"' + (b"A" * 50000) + b'"}')
        assert len(bomb_gz) < 1024
        bomb_s3 = boto3.client(
            "s3",
            region_name="us-east-1",
            aws_access_key_id=_cred("ak"),
            aws_secret_access_key=_cred("sk"),
        )
        bomb_stub = Stubber(bomb_s3)
        bomb_stub.add_response(
            "list_objects_v2",
            {"IsTruncated": False, "Contents": [{"Key": "bomb.cdx.json.gz", "Size": len(bomb_gz)}]},
        )
        bomb_stub.add_response(
            "get_object",
            {
                "ContentLength": len(bomb_gz),
                "Body": StreamingBody(io.BytesIO(bomb_gz), len(bomb_gz)),
            },
        )
        with bomb_stub:
            bomb_backend = S3SbomBackend(
                bucket="corp-sboms", max_sbom_bytes=1024, max_concurrency=1, client=bomb_s3
            )
            with pytest.raises(BackendQueryError, match="Decompressed SBOM"):
                bomb_backend.load()

        # 3) Thread-safe concurrent downloads preserve exact listing order.
        payloads = {
            f"k{i:02d}.cdx.json": _cdx_bytes(("requests", f"2.{i}.0", f"pkg:pypi/requests@2.{i}.0"))
            for i in range(6)
        }

        class _FakeS3:
            def list_objects_v2(self, **_kw: Any) -> dict[str, Any]:
                return {
                    "IsTruncated": False,
                    "Contents": [{"Key": k, "Size": len(v)} for k, v in payloads.items()],
                }

            def get_object(self, **kwargs: Any) -> dict[str, Any]:
                raw = payloads[str(kwargs["Key"])]
                return {"ContentLength": len(raw), "Body": StreamingBody(io.BytesIO(raw), len(raw))}

        seq = S3SbomBackend(bucket="corp-sboms", max_concurrency=1, client=_FakeS3())
        par = S3SbomBackend(bucket="corp-sboms", max_concurrency=4, client=_FakeS3())
        assert seq.find_components((_query(),)) == par.find_components((_query(),))


# ---------------------------------------------------------------------------
# GCP Resilience & SBOM_REFERENCE Verification
# ---------------------------------------------------------------------------


class TestGcpResilienceAndSbomReference:
    def test_gcp_token_auto_refresh_alias_and_401_retry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ZEROBOM_GCP_TOKEN", _cred("gcp-alias"))
        provider = GcpTokenProvider(use_adc=False)
        assert provider.get_token() == _cred("gcp-alias")

        monkeypatch.delenv("ZEROBOM_GCP_TOKEN", raising=False)
        monkeypatch.delenv("ZEROBOM_GCP_ACCESS_TOKEN", raising=False)
        monkeypatch.delenv("GOOGLE_OAUTH_ACCESS_TOKEN", raising=False)
        with pytest.raises(BackendConfigError, match="ZEROBOM_GCP_TOKEN"):
            GcpTokenProvider(use_adc=False)

        class _MockCreds:
            def __init__(self) -> None:
                self.token = _cred("v1")
                self.valid = True
                self.expired = False
                self.expiry = datetime.now(UTC) + timedelta(minutes=30)
                self.quota_project_id = "quota-proj"
                self.refresh_calls = 0

            def refresh(self, _req: Any) -> None:
                self.refresh_calls += 1
                self.token = _cred(f"v{self.refresh_calls + 1}")
                self.expired = False
                self.valid = True
                self.expiry = datetime.now(UTC) + timedelta(minutes=30)

        creds = _MockCreds()
        dyn = GcpTokenProvider(credentials=creds)
        assert dyn.quota_project_id == "quota-proj"
        assert dyn.get_token() == _cred("v1")
        creds.expiry = datetime.now(UTC) + timedelta(seconds=10)
        assert dyn.get_token() == _cred("v2")

        # 401 triggers single force_refresh and 429 uses Retry-After backoff.
        calls: list[tuple[str, str]] = []
        sleeps: list[float] = []

        def _handler(req: httpx.Request) -> httpx.Response:
            calls.append((req.headers["Authorization"], req.headers.get("X-Goog-User-Project", "")))
            if len(calls) == 1:
                return httpx.Response(401)
            if len(calls) == 2:
                return httpx.Response(429, headers={"Retry-After": "1.5"})
            return httpx.Response(
                200,
                json={
                    "occurrences": [
                        {
                            "name": "projects/p/locations/us/occurrences/1",
                            "resourceUri": "https://us-docker.pkg.dev/p/r/img@sha256:111",
                            "kind": "PACKAGE",
                            "package": {
                                "name": "openssl",
                                "packageType": "DEB",
                                "cpeUri": "cpe:2.3:o:debian:debian_linux:11:*:*:*:*:*:*:*",
                                "version": {"name": "1.1.1n", "revision": "0+deb11u4"},
                            },
                        }
                    ]
                },
            )

        client = httpx.Client(transport=httpx.MockTransport(_handler))
        try:
            aa = GcpArtifactAnalysisBackend(
                project_id="my-proj",
                location="us",
                token_provider=dyn,
                http_client=client,
                sleep_fn=sleeps.append,
            )
            hits = aa.find_components(
                (_query("pkg:deb/debian/openssl", "openssl", "deb", "Debian:11"),)
            )
            assert len(hits) == 1
            assert hits[0].distro_qualifier == "debian-11"
            assert calls[0][0] == f"Bearer {_cred('v2')}"
            assert calls[1][0] == f"Bearer {_cred('v3')}"
            assert calls[2][1] == "quota-proj"
            assert sleeps == [1.5]
        finally:
            client.close()

    def test_gcp_sbom_reference_sha256_ssrf_and_gcs_gzip(self) -> None:
        sbom_raw = gzip.compress(_cdx_bytes(("requests", "2.30.0", "pkg:pypi/requests@2.30.0")))
        expected_sha = hashlib.sha256(sbom_raw).hexdigest()
        good_gs = "gs://verified-sboms/app/image.cdx.json.gz"

        def _handler(req: httpx.Request) -> httpx.Response:
            path = req.url.raw_path.split(b"?", 1)[0]
            if path == b"/v1/projects/my-proj/occurrences":
                assert 'kind="SBOM_REFERENCE"' in req.url.params.get("filter", "")
                return httpx.Response(
                    200,
                    json={
                        "occurrences": [
                            {
                                "name": "projects/my-proj/occurrences/sbom-1",
                                "resourceUri": "https://us-docker.pkg.dev/my-proj/repo/web@sha256:aaa",
                                "kind": "SBOM_REFERENCE",
                                "sbomReference": {
                                    "payload": {
                                        "predicate": {
                                            "location": good_gs,
                                            "digest": {"sha256": expected_sha},
                                        }
                                    }
                                },
                            }
                        ]
                    },
                )
            if path == b"/storage/v1/b/verified-sboms/o/app%2Fimage.cdx.json.gz":
                return httpx.Response(200, content=sbom_raw)
            return httpx.Response(404)

        client = httpx.Client(transport=httpx.MockTransport(_handler))
        try:
            aa = GcpArtifactAnalysisBackend(
                project_id="my-proj",
                mode="sbom_reference",
                allowed_sbom_buckets=("verified-sboms",),
                access_token=_cred("gcp"),
                http_client=client,
            )
            case = build_default_conformance_case(backend_name="gcp_artifact_analysis")
            matches = assert_backend_conformance(aa, case)
            assert len(matches) == 1
            assert matches[0].asset is not None
            assert (
                matches[0].asset.asset_id == "https://us-docker.pkg.dev/my-proj/repo/web@sha256:aaa"
            )
        finally:
            client.close()

        # Tampered digest must fail closed BEFORE decompression/parsing.
        tamper_client = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: (
                    httpx.Response(
                        200,
                        json={
                            "occurrences": [
                                {
                                    "name": "occ/1",
                                    "kind": "SBOM_REFERENCE",
                                    "sbomReference": {
                                        "payload": {
                                            "predicate": {
                                                "location": good_gs,
                                                "digest": {"sha256": "0" * 64},
                                            }
                                        }
                                    },
                                }
                            ]
                        },
                    )
                    if b"/occurrences" in req.url.raw_path
                    else httpx.Response(200, content=sbom_raw)
                )
            )
        )
        try:
            tamper_aa = GcpArtifactAnalysisBackend(
                project_id="my-proj",
                mode="sbom_reference",
                access_token=_cred("gcp"),
                http_client=tamper_client,
            )
            with pytest.raises(BackendQueryError, match="SHA-256 digest mismatch"):
                tamper_aa.find_components((_query(),))
        finally:
            tamper_client.close()

        # Non-gs:// location rejected (SSRF protection).
        ssrf_client = httpx.Client(
            transport=httpx.MockTransport(
                lambda _req: httpx.Response(
                    200,
                    json={
                        "occurrences": [
                            {
                                "name": "occ/ssrf",
                                "kind": "SBOM_REFERENCE",
                                "sbomReference": {
                                    "payload": {
                                        "predicate": {
                                            "location": "https://169.254.169.254/latest/meta-data/",
                                        }
                                    }
                                },
                            }
                        ]
                    },
                )
            )
        )
        try:
            ssrf_aa = GcpArtifactAnalysisBackend(
                project_id="my-proj",
                mode="sbom_reference",
                access_token=_cred("gcp"),
                http_client=ssrf_client,
            )
            with pytest.raises(BackendQueryError, match="non-gs://"):
                ssrf_aa.find_components((_query(),))
        finally:
            ssrf_client.close()

        # GcsSbomBackend: gzip + userProject + gzip bomb guard.
        bomb_gz = gzip.compress(b'{"bomFormat":"CycloneDX","pad":"' + (b"B" * 50000) + b'"}')
        gcs_client = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: (
                    httpx.Response(
                        200,
                        json={"items": [{"name": "bomb.cdx.json.gz", "size": str(len(bomb_gz))}]},
                    )
                    if req.url.path == "/storage/v1/b/gcs-bomb-bucket/o"
                    else httpx.Response(200, content=bomb_gz)
                )
            )
        )
        try:
            gcs_bomb = GcsSbomBackend(
                bucket="gcs-bomb-bucket",
                user_project="bill-proj",
                access_token=_cred("gcs"),
                max_sbom_bytes=1024,
                http_client=gcs_client,
            )
            with pytest.raises(BackendQueryError, match="Decompressed SBOM"):
                gcs_bomb.load()
        finally:
            gcs_client.close()


# ---------------------------------------------------------------------------
# Azure Resilience, Quota Pacing, Sovereign Clouds & SAS '+' Preservation
# ---------------------------------------------------------------------------


class TestAzureResilienceAndQuota:
    def test_azure_token_refresh_presets_and_scope_validation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ZEROBOM_AZURE_TOKEN", _cred("az-alias"))
        static_prov = AzureTokenProvider(use_default_credential=False)
        assert static_prov.get_token() == _cred("az-alias")

        monkeypatch.delenv("ZEROBOM_AZURE_TOKEN", raising=False)
        monkeypatch.delenv("ZEROBOM_AZURE_ACCESS_TOKEN", raising=False)
        with pytest.raises(BackendConfigError, match="ZEROBOM_AZURE_TOKEN"):
            AzureTokenProvider(use_default_credential=False)

        now = [1000.0]

        class _FakeToken:
            def __init__(self, tok: str, exp: float) -> None:
                self.token = tok
                self.expires_on = exp

        class _FakeCred:
            def __init__(self) -> None:
                self.calls = 0

            def get_token(self, _scope: str) -> _FakeToken:
                self.calls += 1
                return _FakeToken(f"az-tok-{self.calls}", now[0] + 120.0)

        dyn = AzureTokenProvider(credential=_FakeCred(), time_fn=lambda: now[0])
        assert dyn.get_token() == "az-tok-1"
        now[0] += 80.0
        assert dyn.get_token() == "az-tok-2"

        # Management group & tenant_scope mutual exclusivity.
        with pytest.raises(BackendConfigError, match="only one of"):
            AzureResourceGraphBackend(
                subscriptions=("12345678-1234-1234-1234-1234567890ab",),
                management_groups=("mg-root",),
                access_token=_cred("az"),
            )
        with pytest.raises(BackendConfigError, match="Invalid Azure cloud preset"):
            AzureResourceGraphBackend(
                tenant_scope=True, cloud="unknown-cloud", access_token=_cred("az")
            )

    def test_azure_resource_graph_quota_pacing_distro_and_snake_case(self) -> None:
        sleeps: list[float] = []
        reqs: list[tuple[str, dict[str, Any]]] = []

        def _handler(req: httpx.Request) -> httpx.Response:
            body = json.loads(req.content.decode("utf-8"))
            reqs.append((str(req.url), body))
            if body["options"].get("$skipToken") is None:
                return httpx.Response(
                    200,
                    headers={
                        "x-ms-user-quota-remaining": "0",
                        "x-ms-user-quota-resets-after": "00:00:04.5",
                    },
                    json={
                        "$skipToken": "pg-2",
                        "data": [
                            {
                                "id": "/subscriptions/s1/a1",
                                "subscriptionId": "s1",
                                "resourceId": "/subscriptions/s1/vm-deb11",
                                "softwareName": "apache_http_server",
                                "softwareVersion": "2.4.54-1",
                                "osPlatform": "Debian11",
                            },
                            {
                                "id": "/subscriptions/s1/a2",
                                "subscriptionId": "s1",
                                "resourceId": "/subscriptions/s1/vm-win",
                                "softwareName": "apache_http_server",
                                "softwareVersion": "2.4.50",
                                "osPlatform": "WindowsServer2019",
                            },
                        ],
                    },
                )
            return httpx.Response(200, json={"data": []})

        client = httpx.Client(transport=httpx.MockTransport(_handler))
        try:
            arg = AzureResourceGraphBackend(
                management_groups=("mg-prod",),
                cloud="usgov",
                access_token=_cred("az"),
                http_client=client,
                sleep_fn=sleeps.append,
            )
            assert arg._api_base_url == "https://management.usgovcloudapi.net"
            deb11_adv = OsvAdvisory(
                id="PRECVE-2026-AZDEB1",
                modified=PUBLISHED_AT,
                published=PUBLISHED_AT,
                summary="Apache on Debian 11",
                affected=(
                    OsvAffected(
                        package=OsvPackage(
                            ecosystem="Debian:11",
                            name="apache-http-server",
                            purl="pkg:deb/debian/apache-http-server",
                        ),
                        ranges=(
                            OsvRange(
                                type="ECOSYSTEM",
                                events=(
                                    OsvRangeEvent(introduced="0"),
                                    OsvRangeEvent(fixed="2.4.56-1"),
                                ),
                            ),
                        ),
                    ),
                ),
            )
            hits = match_advisory_with_backend(deb11_adv, arg)
            # Only the Debian 11 VM matches; Windows VM excluded; quota delay honored!
            assert len(hits) == 1
            assert hits[0].asset is not None
            assert hits[0].asset.asset_id.endswith("/vm-deb11")
            assert sleeps == [4.5]
            assert reqs[0][1]["managementGroups"] == ["mg-prod"]
            assert "apache_http_server" in reqs[0][1]["query"]
        finally:
            client.close()

    def test_azure_blob_sas_plus_preservation_archive_skip_and_gzip(self) -> None:
        cdx_gz = gzip.compress(_cdx_bytes(("requests", "2.30.0", "pkg:pypi/requests@2.30.0")))
        sas_with_plus = "sv=2022-11-02&sp=rl&sig=abc+def=="
        seen_sigs: list[str] = []

        xml_list = (
            '<?xml version="1.0" encoding="utf-8"?>'
            "<EnumerationResults><Blobs>"
            "<Blob><Name>archived.cdx.json</Name>"
            "<Properties><Content-Length>200</Content-Length><AccessTier>Archive</AccessTier></Properties>"
            "</Blob>"
            "<Blob><Name>hot/app.cdx.json.gz</Name>"
            f"<Properties><Content-Length>{len(cdx_gz)}</Content-Length>"
            "<AccessTier>Hot</AccessTier><Content-Encoding>gzip</Content-Encoding></Properties>"
            "</Blob>"
            "</Blobs><NextMarker /></EnumerationResults>"
        ).encode()

        def _handler(req: httpx.Request) -> httpx.Response:
            seen_sigs.append(req.url.params.get("sig", ""))
            if req.url.path == "/sboms":
                return httpx.Response(200, content=xml_list)
            if req.url.path == "/sboms/hot/app.cdx.json.gz":
                return httpx.Response(200, content=cdx_gz)
            raise AssertionError(
                f"Unexpected blob GET (archived blob should be skipped): {req.url}"
            )

        client = httpx.Client(transport=httpx.MockTransport(_handler))
        try:
            blob = AzureBlobSbomBackend(
                account_name="secblobs",
                container="sboms",
                sas_token=sas_with_plus,
                cloud="usgov",
                http_client=client,
            )
            assert blob._endpoint_url == "https://secblobs.blob.core.usgovcloudapi.net"
            case = build_default_conformance_case(backend_name="azure_blob_sbom")
            matches = assert_backend_conformance(blob, case)
            assert len(matches) == 1
            assert seen_sigs and all(sig == "abc+def==" for sig in seen_sigs)
        finally:
            client.close()

        # skip_archived=False fails closed on Archive blobs.
        strict_client = httpx.Client(
            transport=httpx.MockTransport(lambda _r: httpx.Response(200, content=xml_list))
        )
        try:
            no_skip = AzureBlobSbomBackend(
                account_name="secblobs",
                container="sboms",
                access_token=_cred("az"),
                skip_archived=False,
                http_client=strict_client,
            )
            with pytest.raises(BackendQueryError, match="Archive access tier"):
                no_skip.load()
        finally:
            strict_client.close()

        # C1 control character inside blob name fails closed.
        c1_xml = (
            '<?xml version="1.0" encoding="utf-8"?>'
            "<EnumerationResults><Blobs><Blob><Name>evil\x9b.cdx.json</Name></Blob></Blobs></EnumerationResults>"
        ).encode()
        c1_client = httpx.Client(
            transport=httpx.MockTransport(lambda _r: httpx.Response(200, content=c1_xml))
        )
        try:
            c1_blob = AzureBlobSbomBackend(
                account_name="secblobs",
                container="sboms",
                access_token=_cred("az"),
                http_client=c1_client,
            )
            with pytest.raises(BackendQueryError, match="control char"):
                c1_blob.load()
        finally:
            c1_client.close()
