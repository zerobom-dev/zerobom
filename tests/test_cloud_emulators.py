"""Real-wire cloud storage emulator integration tests (LocalStack, fake-gcs-server, Azurite).

Tests auto-skip cleanly when corresponding emulator endpoint environment variables are unset so
default offline ``pytest`` runs stay 100% self-contained.
"""

from __future__ import annotations

import base64
import contextlib
import gzip
import hashlib
import hmac
import json
import os
from urllib.parse import parse_qsl, quote, urlencode

import boto3
import httpx
import pytest

from zerobom.backends import assert_backend_conformance, build_default_conformance_case
from zerobom_aws import S3SbomBackend
from zerobom_azure import AzureBlobSbomBackend
from zerobom_gcp import GcsSbomBackend

pytestmark = pytest.mark.emulator

# Azurite's well-known public devstoreaccount1 emulator key (documented by Microsoft Learn).
_AZURITE_PUBLIC_EMULATOR_KEY = (
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
)


def _sample_cdx_bytes() -> bytes:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "type": "library",
                    "name": "requests",
                    "version": "2.30.0",
                    "purl": "pkg:pypi/requests@2.30.0",
                }
            ],
        }
    ).encode("utf-8")


def _build_azurite_account_sas() -> str:
    """Construct a valid Azure Storage Account SAS token for Azurite devstoreaccount1."""
    account_key = base64.b64decode(_AZURITE_PUBLIC_EMULATOR_KEY)
    signed_version = "2023-11-03"
    string_to_sign = "\n".join(
        [
            "devstoreaccount1",
            "rwdlac",
            "b",
            "co",
            "2020-01-01T00:00:00Z",
            "2035-01-01T00:00:00Z",
            "",
            "http,https",
            signed_version,
            "",
            "",
        ]
    )
    sig = base64.b64encode(
        hmac.new(account_key, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
    ).decode("ascii")
    return urlencode(
        {
            "sv": signed_version,
            "ss": "b",
            "srt": "co",
            "sp": "rwdlac",
            "st": "2020-01-01T00:00:00Z",
            "se": "2035-01-01T00:00:00Z",
            "spr": "http,https",
            "sig": sig,
        }
    )


def test_localstack_s3_sbom_plain_and_gzip() -> None:
    endpoint = os.environ.get("ZEROBOM_EMULATOR_S3_URL")
    if not endpoint:
        pytest.skip("ZEROBOM_EMULATOR_S3_URL is not set.")

    bucket = "zerobom-emulator-sboms"
    s3 = boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name="us-east-1",
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
    )
    with contextlib.suppress(Exception):
        s3.create_bucket(Bucket=bucket)

    s3.put_object(
        Bucket=bucket,
        Key="prod/app.cdx.json.gz",
        Body=gzip.compress(_sample_cdx_bytes()),
    )

    backend = S3SbomBackend(
        bucket=bucket,
        prefix="prod/",
        endpoint_url=endpoint,
        allow_insecure_http=True,
        region_name="us-east-1",
    )
    try:
        case = build_default_conformance_case(backend_name="s3_sbom")
        matches = assert_backend_conformance(backend, case)
        assert len(matches) == 1
    finally:
        backend.close()


def test_fake_gcs_server_sbom_plain_and_gzip() -> None:
    endpoint = os.environ.get("ZEROBOM_EMULATOR_GCS_URL")
    if not endpoint:
        pytest.skip("ZEROBOM_EMULATOR_GCS_URL is not set.")

    bucket = "zerobom-emulator-gcs"
    with httpx.Client(verify=False, timeout=10.0) as client:  # noqa: S501 - local emulator TLS
        client.post(f"{endpoint}/storage/v1/b", json={"name": bucket})
        client.post(
            f"{endpoint}/upload/storage/v1/b/{bucket}/o",
            params={"uploadType": "media", "name": "prod/app.cdx.json.gz"},
            content=gzip.compress(_sample_cdx_bytes()),
            headers={"Content-Type": "application/gzip"},
        )

    backend = GcsSbomBackend(
        bucket=bucket,
        prefix="prod/",
        api_base_url=endpoint,
        allow_insecure_http=True,
        verify_tls=False,
        access_token="emulator-token",  # noqa: S106 - local emulator placeholder
    )
    try:
        case = build_default_conformance_case(backend_name="gcs_sbom")
        matches = assert_backend_conformance(backend, case)
        assert len(matches) == 1
    finally:
        backend.close()


def test_azurite_blob_sbom_plain_and_gzip() -> None:
    endpoint = os.environ.get("ZEROBOM_EMULATOR_AZBLOB_URL")
    if not endpoint:
        pytest.skip("ZEROBOM_EMULATOR_AZBLOB_URL is not set.")

    sas_query = _build_azurite_account_sas()
    sas_params = dict(parse_qsl(sas_query))
    container = "sboms"
    with httpx.Client(timeout=10.0) as client:
        client.put(f"{endpoint}/{container}", params={**sas_params, "restype": "container"})
        blob_name = quote("prod/app.cdx.json.gz", safe="/")
        put_resp = client.put(
            f"{endpoint}/{container}/{blob_name}",
            params=sas_params,
            content=gzip.compress(_sample_cdx_bytes()),
            headers={"x-ms-blob-type": "BlockBlob", "x-ms-version": "2023-11-03"},
        )
        assert put_resp.status_code in (200, 201), put_resp.text

    backend = AzureBlobSbomBackend(
        account_name="devstoreaccount1",
        container=container,
        prefix="prod/",
        endpoint_url=endpoint,
        allow_insecure_http=True,
        sas_token=sas_query,
    )
    try:
        case = build_default_conformance_case(backend_name="azure_blob_sbom")
        matches = assert_backend_conformance(backend, case)
        assert len(matches) == 1
    finally:
        backend.close()
