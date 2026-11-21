"""Comprehensive offline unit & conformance tests for Milestone 2.1B backends.

Covers shared transport/TLS/config validators (``_http.py``), ``DependencyTrackBackend``,
``OciSbomBackend``, and ``K8sSbomBackend`` using 100% offline ``httpx.MockTransport``
handlers and ``certifi`` CA material.
"""

from __future__ import annotations

import base64
import hashlib
import json
import ssl
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import certifi
import httpx
import pytest
import yaml

from zerobom.backends import (
    BackendConfigError,
    BackendQueryError,
    BackendRegistry,
    DependencyTrackBackend,
    K8sSbomBackend,
    OciSbomBackend,
    assert_backend_conformance,
    build_default_conformance_case,
    parse_backend_options,
)
from zerobom.backends._http import (
    parse_bool_opt,
    parse_float_opt,
    parse_int_opt,
    parse_optional_str_opt,
    parse_str_list_opt,
    read_bounded_response,
    reject_unknown_config_keys,
    resolve_tls_verify,
    validate_api_base_url,
)
from zerobom.backends.oci_sbom import parse_oci_image_ref
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

PUBLISHED_AT = datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)


def _cred(prefix: str) -> str:
    """Return synthetic non-secret credential strings without triggering S105/S106 literals."""
    return f"{prefix}-unit-test-placeholder"


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
        "name": "oci-spdx-fixture",
        "documentNamespace": "https://example.org/spdx/oci-fixture",
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
# 1. Shared _http.py Transport, TLS & Option Validators
# ---------------------------------------------------------------------------


class TestSharedHttpAndConfigHelpers:
    def test_validate_api_base_url_enforces_scheme_creds_and_traversal(self) -> None:
        assert validate_api_base_url("https://api.internal.example/") == (
            "https://api.internal.example"
        )
        assert validate_api_base_url("http://localhost:8080/api/", allow_insecure_http=True) == (
            "http://localhost:8080/api"
        )

        with pytest.raises(BackendConfigError, match="https://"):
            validate_api_base_url("http://api.internal.example")
        with pytest.raises(BackendConfigError, match="credentials"):
            validate_api_base_url("https://user:secret@api.internal.example")
        with pytest.raises(BackendConfigError, match="control characters"):
            validate_api_base_url("https://api.internal.example/\nHost: evil")
        with pytest.raises(BackendConfigError, match="query"):
            validate_api_base_url("https://api.internal.example/?x=1")
        with pytest.raises(BackendConfigError, match="fragment"):
            validate_api_base_url("https://api.internal.example/#frag", allow_query=True)
        with pytest.raises(BackendConfigError, match="traversal"):
            validate_api_base_url("https://api.internal.example/v1/../admin")

    def test_read_bounded_response_blocks_content_length_and_stream_overflow(self) -> None:
        def _handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/huge-header":
                return httpx.Response(200, headers={"Content-Length": "4096"}, content=b"tiny")
            return httpx.Response(200, content=b"x" * 1024)

        client = httpx.Client(transport=httpx.MockTransport(_handler))
        try:
            with pytest.raises(BackendQueryError, match="Content-Length"):
                read_bounded_response(
                    client,
                    "GET",
                    "https://api.internal.example/huge-header",
                    max_bytes=512,
                    backend_name="test",
                )
            with pytest.raises(BackendQueryError, match="exceeds limit"):
                read_bounded_response(
                    client,
                    "GET",
                    "https://api.internal.example/stream-overflow",
                    max_bytes=512,
                    backend_name="test",
                )
        finally:
            client.close()

    def test_resolve_tls_verify_with_certifi_bundle_and_conflict_guards(self) -> None:
        ca_path = Path(certifi.where())
        pem_text = ca_path.read_text(encoding="utf-8")

        ctx_from_file = resolve_tls_verify(verify_tls=True, ca_bundle=ca_path)
        ctx_from_pem = resolve_tls_verify(verify_tls=True, ca_pem_data=pem_text)
        assert isinstance(ctx_from_file, ssl.SSLContext)
        assert isinstance(ctx_from_pem, ssl.SSLContext)
        assert resolve_tls_verify(verify_tls=False) is False

        with pytest.raises(BackendConfigError, match="Invalid TLS"):
            resolve_tls_verify(verify_tls=True, ca_pem_data="not-a-valid-pem-cert")
        with pytest.raises(BackendConfigError, match="verify_tls=False"):
            resolve_tls_verify(verify_tls=False, ca_bundle=ca_path)
        with pytest.raises(BackendConfigError, match="verify_tls=False"):
            resolve_tls_verify(verify_tls=False, ca_pem_data=pem_text)
        with pytest.raises(BackendConfigError, match="client_cert and client_key"):
            resolve_tls_verify(verify_tls=True, client_cert=ca_path)

    def test_option_parsers_reject_invalid_types_booleans_and_nan(self) -> None:
        with pytest.raises(BackendConfigError, match="Unsupported configuration"):
            reject_unknown_config_keys({"bad_opt": 1}, frozenset({"ok"}), backend_name="demo")

        assert parse_bool_opt({"flag": "YES"}, "flag", default=False) is True
        assert parse_bool_opt({"flag": "off"}, "flag", default=True) is False
        with pytest.raises(BackendConfigError, match="boolean"):
            parse_bool_opt({"flag": "maybe"}, "flag", default=False)

        assert parse_int_opt({"n": "42"}, "n", default=1, min_value=1, max_value=100) == 42
        with pytest.raises(BackendConfigError, match="integer"):
            parse_int_opt({"n": True}, "n", default=1, min_value=1, max_value=100)

        assert (
            parse_float_opt({"t": "12.5"}, "t", default=1.0, min_value=0.5, max_value=30.0) == 12.5
        )
        with pytest.raises(BackendConfigError, match="between"):
            parse_float_opt({"t": "nan"}, "t", default=1.0, min_value=0.5, max_value=30.0)
        with pytest.raises(BackendConfigError, match="number"):
            parse_float_opt({"t": False}, "t", default=1.0, min_value=0.5, max_value=30.0)

        assert parse_str_list_opt({"imgs": "a:1, b:2"}, "imgs") == ("a:1", "b:2")
        assert parse_str_list_opt({"imgs": ["x:1", "y:2"]}, "imgs") == ("x:1", "y:2")
        assert parse_optional_str_opt({"prefix": ""}, "prefix", allow_empty=True) == ""

        # Control chars around commas/keys must be rejected before .strip().
        with pytest.raises(BackendConfigError, match="control characters"):
            parse_str_list_opt({"imgs": "a:1,b:2\r\n"}, "imgs")
        with pytest.raises(BackendConfigError, match="control characters"):
            parse_backend_options(("key\n=val",))

        # HTTP error URL redaction must strip query secrets (?sig=...) and secret webhook paths.
        def _boom(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection reset")

        boom_client = httpx.Client(transport=httpx.MockTransport(_boom))
        try:
            with pytest.raises(BackendQueryError) as exc_info:
                read_bounded_response(
                    boom_client,
                    "GET",
                    "https://storage.example/blob.json?sig=TOP_SECRET_SAS_TOKEN",
                    backend_name="test",
                )
            assert "TOP_SECRET_SAS_TOKEN" not in str(exc_info.value)

            with pytest.raises(BackendQueryError) as exc_path:
                read_bounded_response(
                    boom_client,
                    "POST",
                    "https://hooks.slack.com/services/T0/B0/SECRET_TOKEN",
                    backend_name="slack",
                    redact_url_path=True,
                )
            assert "SECRET_TOKEN" not in str(exc_path.value)
        finally:
            boom_client.close()


# ---------------------------------------------------------------------------
# 2. OWASP Dependency-Track Backend
# ---------------------------------------------------------------------------


class TestDependencyTrackBackend:
    def test_conformance_and_registry_discovery(self) -> None:
        assert "dependency_track" in BackendRegistry().list_backends()

        def _handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/api/v1/component/identity"
            assert request.headers["X-Api-Key"] == _cred("dt")
            pkg_name = request.url.params.get("name")
            if pkg_name == "requests":
                return httpx.Response(
                    200,
                    headers={"X-Total-Count": "1"},
                    json=[
                        {
                            "uuid": "comp-1111",
                            "name": "requests",
                            "version": "2.30.0",
                            "purl": "pkg:pypi/requests@2.30.0",
                            "project": {
                                "uuid": "proj-aaaa",
                                "name": "billing-api",
                                "version": "1.4.2",
                                "classifier": "APPLICATION",
                            },
                        }
                    ],
                )
            return httpx.Response(200, headers={"X-Total-Count": "0"}, json=[])

        client = httpx.Client(transport=httpx.MockTransport(_handler))
        backend = DependencyTrackBackend(
            base_url="https://dtrack.internal",
            api_key=_cred("dt"),
            http_client=client,
        )
        try:
            case = build_default_conformance_case(backend_name="dependency_track")
            matches = assert_backend_conformance(backend, case)
            assert len(matches) == 1
            assert matches[0].installed_version == "2.30.0"
            assert matches[0].asset is not None
            assert matches[0].asset.asset_id == "dt-project:proj-aaaa"
            assert matches[0].asset.location == "https://dtrack.internal/projects/proj-aaaa"
        finally:
            client.close()

        # Verify Maven group+name lookup in default coordinates mode and legacy query_mode="purl".
        seen_params: list[dict[str, str]] = []

        def _mode_handler(request: httpx.Request) -> httpx.Response:
            seen_params.append(dict(request.url.params))
            return httpx.Response(
                200,
                headers={"X-Total-Count": "1"},
                json=[
                    {
                        "uuid": "comp-log4j",
                        "group": "org.apache.logging.log4j",
                        "name": "log4j-core",
                        "version": "2.14.1",
                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                        "project": {"uuid": "proj-jvm", "name": "jvm-svc", "version": "1.0"},
                    }
                ],
            )

        mode_client = httpx.Client(transport=httpx.MockTransport(_mode_handler))
        maven_q = PackageQuery(
            canonical_purl="pkg:maven/org.apache.logging.log4j/log4j-core",
            ecosystem="maven",
            osv_ecosystem="Maven",
            namespace="org.apache.logging.log4j",
            name="log4j-core",
        )
        try:
            coord_backend = DependencyTrackBackend(
                base_url="https://dtrack.internal",
                api_key=_cred("dt"),
                http_client=mode_client,
            )
            assert len(coord_backend.find_components((maven_q,))) == 1
            assert seen_params[-1]["group"] == "org.apache.logging.log4j"
            assert seen_params[-1]["name"] == "log4j-core"
            assert "purl" not in seen_params[-1]

            purl_backend = DependencyTrackBackend(
                base_url="https://dtrack.internal",
                api_key=_cred("dt"),
                query_mode="purl",
                http_client=mode_client,
            )
            assert len(purl_backend.find_components((maven_q,))) == 1
            assert seen_params[-1]["purl"] == "pkg:maven/org.apache.logging.log4j/log4j-core"
        finally:
            mode_client.close()

    def test_pagination_dedup_queries_and_sarif_integration(self) -> None:
        calls = 0

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            page = request.url.params.get("pageNumber")
            if page == "1":
                return httpx.Response(
                    200,
                    headers={"X-Total-Count": "3"},
                    json=[
                        {
                            "uuid": "comp-1",
                            "name": "requests",
                            "version": "2.28.0",
                            "purl": "pkg:pypi/requests@2.28.0",
                            "project": {"uuid": "proj-1", "name": "svc-alpha", "version": "1.0"},
                        },
                        {
                            "uuid": "comp-2",
                            "name": "requests",
                            "version": "2.29.0",
                            "purl": "pkg:pypi/requests@2.29.0",
                            "project": {"uuid": "proj-2", "name": "svc-beta", "version": "2.0"},
                        },
                    ],
                )
            return httpx.Response(
                200,
                headers={"X-Total-Count": "3"},
                json=[
                    {
                        "uuid": "comp-3",
                        "name": "requests",
                        "version": "2.30.0",
                        "purl": "pkg:pypi/requests@2.30.0",
                        "project": {"uuid": "proj-3", "name": "svc-gamma", "version": "3.0"},
                    }
                ],
            )

        client = httpx.Client(transport=httpx.MockTransport(_handler))
        backend = DependencyTrackBackend(
            base_url="https://dtrack.internal",
            bearer_token=_cred("jwt"),
            page_size=2,
            max_pages=5,
            http_client=client,
        )
        try:
            q = _requests_query()
            found = backend.find_components((q, q))
            # Duplicate queries in one batch only trigger one paginated fetch sequence (2 pages).
            assert calls == 2
            assert {comp.asset.asset_id for comp in found} == {
                "dt-project:proj-1",
                "dt-project:proj-2",
                "dt-project:proj-3",
            }
            # Empty query short-circuits with zero HTTP requests.
            assert backend.find_components(()) == ()
            assert calls == 2
        finally:
            client.close()

        # Verify SARIF integration emits distinct remote URIs & fingerprints per project.
        advisory = OsvAdvisory(
            id="PRECVE-2026-DT000001",
            modified=PUBLISHED_AT,
            published=PUBLISHED_AT,
            summary="Requests vulnerability across DT projects",
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
        from zerobom.backends import match_advisory_with_backend

        class _StaticDt:
            name = "dependency_track"

            def find_components(self, queries: Any) -> Any:
                del queries
                return found

        matches = match_advisory_with_backend(advisory, _StaticDt())
        sarif = build_sarif_log((PipelineOutcome(osv=advisory, matches=matches),))
        results = sarif["runs"][0]["results"]
        assert len(results) == 3
        uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results}
        assert uris == {
            "dtrack.internal/projects/proj-1",
            "dtrack.internal/projects/proj-2",
            "dtrack.internal/projects/proj-3",
        }
        fps = {r["partialFingerprints"]["primaryLocationLineHash"] for r in results}
        assert len(fps) == 3
        assert results[0]["properties"]["backend"] == "dependency_track"
        assert results[0]["properties"]["assetType"] == "dependency_track_project"

    def test_pagination_max_pages_fails_closed_and_error_handling(self) -> None:
        def _infinite_pages(request: httpx.Request) -> httpx.Response:
            del request
            return httpx.Response(
                200,
                headers={"X-Total-Count": "99"},
                json=[
                    {
                        "uuid": "comp-1",
                        "name": "requests",
                        "version": "2.30.0",
                        "purl": "pkg:pypi/requests@2.30.0",
                        "project": {"uuid": "proj-1", "name": "svc", "version": "1.0"},
                    }
                ],
            )

        client = httpx.Client(transport=httpx.MockTransport(_infinite_pages))
        backend = DependencyTrackBackend(
            base_url="https://dtrack.internal",
            api_key=_cred("dt"),
            page_size=1,
            max_pages=2,
            http_client=client,
        )
        try:
            with pytest.raises(BackendQueryError, match="max_pages=2"):
                backend.find_components((_requests_query(),))
        finally:
            client.close()

        for bad_status in (302, 401, 403, 429, 500):
            err_client = httpx.Client(
                transport=httpx.MockTransport(
                    lambda req, code=bad_status: httpx.Response(
                        code, headers={"Location": "https://x"}
                    )
                )
            )
            err_backend = DependencyTrackBackend(
                base_url="https://dtrack.internal",
                api_key=_cred("dt"),
                http_client=err_client,
            )
            try:
                with pytest.raises(BackendQueryError):
                    err_backend.find_components((_requests_query(),))
            finally:
                err_client.close()

        bad_json_client = httpx.Client(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"unexpected": 1}))
        )
        bad_json_backend = DependencyTrackBackend(
            base_url="https://dtrack.internal",
            api_key=_cred("dt"),
            http_client=bad_json_client,
        )
        try:
            with pytest.raises(BackendQueryError, match="JSON array"):
                bad_json_backend.find_components((_requests_query(),))
        finally:
            bad_json_client.close()

    def test_from_config_env_fallbacks_and_secret_redaction(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret_key = _cred("dt-env-secret")
        monkeypatch.setenv("ZEROBOM_DT_URL", "https://dt-env.internal")
        monkeypatch.setenv("ZEROBOM_DT_API_KEY", secret_key)
        monkeypatch.delenv("ZEROBOM_DT_BEARER_TOKEN", raising=False)

        backend = DependencyTrackBackend.from_config({"project_uuid": "proj-1234"})
        try:
            assert secret_key not in repr(backend)
            assert "auth='api_key'" in repr(backend)
        finally:
            backend.close()

        with pytest.raises(BackendConfigError, match="Unsupported configuration"):
            DependencyTrackBackend.from_config({"unknown": "val"})

        monkeypatch.delenv("ZEROBOM_DT_URL", raising=False)
        monkeypatch.delenv("ZEROBOM_DT_API_KEY", raising=False)
        with pytest.raises(BackendConfigError, match="base_url"):
            DependencyTrackBackend.from_config({})


# ---------------------------------------------------------------------------
# 3. OCI Container Registry SBOM Backend
# ---------------------------------------------------------------------------


class TestOciSbomBackend:
    def test_conformance_and_registry_discovery(self) -> None:
        assert "oci_sbom" in BackendRegistry().list_backends()

        sbom_blob = _cdx_bytes(("requests", "2.30.0", "pkg:pypi/requests@2.30.0"))
        blob_digest = f"sha256:{hashlib.sha256(sbom_blob).hexdigest()}"
        ref_manifest = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "artifactType": "application/vnd.cyclonedx+json",
                "layers": [
                    {
                        "mediaType": "application/vnd.cyclonedx+json",
                        "digest": blob_digest,
                        "size": len(sbom_blob),
                    }
                ],
            }
        ).encode("utf-8")
        ref_digest = f"sha256:{hashlib.sha256(ref_manifest).hexdigest()}"
        img_manifest = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "layers": [],
            }
        ).encode("utf-8")
        img_digest = f"sha256:{hashlib.sha256(img_manifest).hexdigest()}"

        def _handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/v2/acme/api/manifests/1.0.0":
                return httpx.Response(
                    200,
                    headers={"Docker-Content-Digest": img_digest},
                    content=img_manifest,
                )
            if path == f"/v2/acme/api/referrers/{img_digest}":
                return httpx.Response(
                    200,
                    json={
                        "schemaVersion": 2,
                        "mediaType": "application/vnd.oci.image.index.v1+json",
                        "manifests": [
                            {
                                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                                "digest": ref_digest,
                                "artifactType": "application/vnd.cyclonedx+json",
                            }
                        ],
                    },
                )
            if path == f"/v2/acme/api/manifests/{ref_digest}":
                return httpx.Response(200, content=ref_manifest)
            if path == f"/v2/acme/api/blobs/{blob_digest}":
                return httpx.Response(200, content=sbom_blob)
            return httpx.Response(404)

        client = httpx.Client(transport=httpx.MockTransport(_handler))
        backend = OciSbomBackend(images=("ghcr.io/acme/api:1.0.0",), http_client=client)
        try:
            case = build_default_conformance_case(backend_name="oci_sbom")
            matches = assert_backend_conformance(backend, case)
            assert len(matches) == 1
            assert matches[0].asset is not None
            assert matches[0].asset.asset_id == f"oci://ghcr.io/acme/api@{img_digest}"
            assert matches[0].asset.asset_type == "oci_image"
        finally:
            client.close()

    def test_bearer_exchange_blob_redirect_strips_auth_and_unwraps_dsse(self) -> None:
        spdx_doc = _spdx_bytes("requests", "2.30.0", "pkg:pypi/requests@2.30.0")
        spdx_digest = f"sha256:{hashlib.sha256(spdx_doc).hexdigest()}"

        cdx_inner = json.loads(_cdx_bytes(("urllib3", "1.26.18", "pkg:pypi/urllib3@1.26.18")))
        in_toto_stmt = json.dumps(
            {
                "_type": "https://in-toto.io/Statement/v1",
                "predicateType": "https://cyclonedx.org/bom",
                "predicate": cdx_inner,
            }
        ).encode("utf-8")
        dsse_env = json.dumps(
            {
                "payloadType": "application/vnd.in-toto+json",
                "payload": base64.b64encode(in_toto_stmt).decode("ascii"),
                "signatures": [{"sig": "dummy"}],
            }
        ).encode("utf-8")
        dsse_digest = f"sha256:{hashlib.sha256(dsse_env).hexdigest()}"

        spdx_ref_manifest = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "artifactType": "application/spdx+json",
                "layers": [{"mediaType": "application/spdx+json", "digest": spdx_digest}],
            }
        ).encode("utf-8")
        spdx_ref_digest = f"sha256:{hashlib.sha256(spdx_ref_manifest).hexdigest()}"

        dsse_ref_manifest = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "artifactType": "application/vnd.dsse.envelope.v1+json",
                "layers": [
                    {
                        "mediaType": "application/vnd.dsse.envelope.v1+json",
                        "digest": dsse_digest,
                    }
                ],
            }
        ).encode("utf-8")
        dsse_ref_digest = f"sha256:{hashlib.sha256(dsse_ref_manifest).hexdigest()}"

        img_manifest = json.dumps({"schemaVersion": 2, "layers": []}).encode("utf-8")
        img_digest = f"sha256:{hashlib.sha256(img_manifest).hexdigest()}"

        minted_cred = _cred("oci-minted")
        basic_pass = _cred("oci-pass")
        seen_redirect_auth = False

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal seen_redirect_auth
            if request.url.host == "auth.docker.io":
                assert "Authorization" in request.headers
                assert request.url.params["service"] == "registry.docker.io"
                assert request.url.params["scope"] == "repository:library/nginx:pull"
                return httpx.Response(200, json={"token": minted_cred})

            if request.url.host == "cdn-blobs.example":
                if "authorization" in {k.lower() for k in request.headers}:
                    seen_redirect_auth = True
                return httpx.Response(200, content=spdx_doc)

            if request.headers.get("Authorization") != f"Bearer {minted_cred}":
                return httpx.Response(
                    401,
                    headers={
                        "WWW-Authenticate": (
                            'Bearer realm="https://auth.docker.io/token",'
                            'service="registry.docker.io",'
                            'scope="repository:library/nginx:pull"'
                        )
                    },
                )

            path = request.url.path
            if path == "/v2/library/nginx/manifests/1.27":
                return httpx.Response(
                    200,
                    headers={"Docker-Content-Digest": img_digest},
                    content=img_manifest,
                )
            if path == f"/v2/library/nginx/referrers/{img_digest}":
                # Exercise OCI 1.0 fallback tag schema on 404.
                return httpx.Response(404)
            fallback_tag = img_digest.replace(":", "-", 1)
            if path == f"/v2/library/nginx/manifests/{fallback_tag}":
                return httpx.Response(
                    200,
                    json={
                        "schemaVersion": 2,
                        "manifests": [
                            {
                                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                                "digest": spdx_ref_digest,
                                "artifactType": "application/spdx+json",
                            },
                            {
                                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                                "digest": dsse_ref_digest,
                                "artifactType": "application/vnd.dsse.envelope.v1+json",
                            },
                        ],
                    },
                )
            if path == f"/v2/library/nginx/manifests/{spdx_ref_digest}":
                return httpx.Response(200, content=spdx_ref_manifest)
            if path == f"/v2/library/nginx/manifests/{dsse_ref_digest}":
                return httpx.Response(200, content=dsse_ref_manifest)
            if path == f"/v2/library/nginx/blobs/{spdx_digest}":
                return httpx.Response(
                    307,
                    headers={"Location": "https://cdn-blobs.example/blobs/spdx.json?sig=abc"},
                )
            if path == f"/v2/library/nginx/blobs/{dsse_digest}":
                return httpx.Response(200, content=dsse_env)
            return httpx.Response(404)

        client = httpx.Client(transport=httpx.MockTransport(_handler))
        backend = OciSbomBackend(
            images=("nginx:1.27",),
            username="robot",
            password=basic_pass,
            http_client=client,
        )
        try:
            assert basic_pass not in repr(backend)
            assert minted_cred not in repr(backend)
            req_hits = backend.find_components((_requests_query(),))
            urllib_hits = backend.find_components((_requests_query("pkg:pypi/urllib3", "urllib3"),))
            assert len(req_hits) == 1
            assert req_hits[0].version == "2.30.0"
            assert len(urllib_hits) == 1
            assert urllib_hits[0].version == "1.26.18"
            assert seen_redirect_auth is False
        finally:
            client.close()

    def test_multiarch_platform_filter_buildkit_attestation_and_tamper_rejection(self) -> None:
        amd64_manifest = json.dumps({"schemaVersion": 2, "layers": []}).encode("utf-8")
        amd64_digest = f"sha256:{hashlib.sha256(amd64_manifest).hexdigest()}"
        arm64_manifest = json.dumps({"schemaVersion": 2, "layers": [{"x": 1}]}).encode("utf-8")
        arm64_digest = f"sha256:{hashlib.sha256(arm64_manifest).hexdigest()}"

        amd64_sbom = _cdx_bytes(("requests", "2.30.0", "pkg:pypi/requests@2.30.0"))
        amd64_sbom_stmt = json.dumps(
            {
                "_type": "https://in-toto.io/Statement/v0.1",
                "predicateType": "https://cyclonedx.org/bom",
                "predicate": json.loads(amd64_sbom),
            }
        ).encode("utf-8")
        amd64_sbom_digest = f"sha256:{hashlib.sha256(amd64_sbom_stmt).hexdigest()}"
        amd64_att_manifest = json.dumps(
            {
                "schemaVersion": 2,
                "layers": [
                    {
                        "mediaType": "application/vnd.in-toto+json",
                        "digest": amd64_sbom_digest,
                    }
                ],
            }
        ).encode("utf-8")
        amd64_att_digest = f"sha256:{hashlib.sha256(amd64_att_manifest).hexdigest()}"

        arm64_att_digest = f"sha256:{'b' * 64}"
        index_bytes = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": amd64_digest,
                        "platform": {"os": "linux", "architecture": "amd64"},
                    },
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": arm64_digest,
                        "platform": {"os": "linux", "architecture": "arm64"},
                    },
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": amd64_att_digest,
                        "annotations": {
                            "vnd.docker.reference.type": "attestation-manifest",
                            "vnd.docker.reference.digest": amd64_digest,
                        },
                    },
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": arm64_att_digest,
                        "annotations": {
                            "vnd.docker.reference.type": "attestation-manifest",
                            "vnd.docker.reference.digest": arm64_digest,
                        },
                    },
                ],
            }
        ).encode("utf-8")
        index_digest = f"sha256:{hashlib.sha256(index_bytes).hexdigest()}"

        requested_paths: list[str] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            requested_paths.append(request.url.path)
            if request.url.path == f"/v2/org/svc/manifests/{index_digest}":
                return httpx.Response(200, content=index_bytes)
            if request.url.path == f"/v2/org/svc/manifests/{amd64_att_digest}":
                return httpx.Response(200, content=amd64_att_manifest)
            if request.url.path == f"/v2/org/svc/blobs/{amd64_sbom_digest}":
                return httpx.Response(200, content=amd64_sbom_stmt)
            if "/referrers/" in request.url.path:
                return httpx.Response(200, json={"schemaVersion": 2, "manifests": []})
            return httpx.Response(404)

        client = httpx.Client(transport=httpx.MockTransport(_handler))
        backend = OciSbomBackend(
            images=(f"ghcr.io/org/svc@{index_digest}",),
            platform="linux/amd64",
            http_client=client,
        )
        try:
            found = backend.find_components((_requests_query(),))
            assert len(found) == 1
            assert arm64_att_digest not in " ".join(requested_paths)
            assert f"/v2/org/svc/referrers/{amd64_digest}" in requested_paths
            assert f"/v2/org/svc/referrers/{arm64_digest}" not in requested_paths
        finally:
            client.close()

        # Verify tampered blob digest fails closed with BackendQueryError.
        expected_blob_digest = f"sha256:{'a' * 64}"
        tamper_ref = json.dumps(
            {
                "schemaVersion": 2,
                "artifactType": "application/vnd.cyclonedx+json",
                "layers": [
                    {
                        "mediaType": "application/vnd.cyclonedx+json",
                        "digest": expected_blob_digest,
                    }
                ],
            }
        ).encode("utf-8")
        tamper_ref_digest = f"sha256:{hashlib.sha256(tamper_ref).hexdigest()}"

        def _tampered_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v2/org/bad/manifests/1.0":
                return httpx.Response(
                    200,
                    headers={"Docker-Content-Digest": f"sha256:{'1' * 64}"},
                    json={"schemaVersion": 2},
                )
            if request.url.path.startswith("/v2/org/bad/referrers/"):
                return httpx.Response(
                    200,
                    json={
                        "manifests": [
                            {
                                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                                "digest": tamper_ref_digest,
                                "artifactType": "application/vnd.cyclonedx+json",
                            }
                        ]
                    },
                )
            if request.url.path.endswith(tamper_ref_digest):
                return httpx.Response(200, content=tamper_ref)
            if request.url.path.endswith(expected_blob_digest):
                return httpx.Response(200, content=amd64_sbom)
            return httpx.Response(404)

        tamper_client = httpx.Client(transport=httpx.MockTransport(_tampered_handler))
        tamper_backend = OciSbomBackend(images=("ghcr.io/org/bad:1.0",), http_client=tamper_client)
        try:
            with pytest.raises(BackendQueryError, match="Digest mismatch"):
                tamper_backend.find_components((_requests_query(),))
        finally:
            tamper_client.close()

    def test_ref_validation_from_config_strict_and_oversized_blob(self) -> None:
        parsed = parse_oci_image_ref("localhost:5000/team/api:v1.2.3")
        assert parsed.registry == "localhost:5000"
        assert parsed.repository == "team/api"
        assert parsed.tag == "v1.2.3"

        for bad_ref in (
            "nginx",
            "https://ghcr.io/org/app:1.0",
            "ghcr.io/org/../secret:1.0",
            "ghcr.io/org/app\n:1.0",
            "ghcr.io/org/app:1.0 extra",
            "user:pass@ghcr.io/org/app:1.0",
        ):
            with pytest.raises(BackendConfigError):
                parse_oci_image_ref(bad_ref)

        cfg_backend = OciSbomBackend.from_config(
            {"images": "ghcr.io/org/a:1.0, ghcr.io/org/b@sha256:" + "0" * 64}
        )
        try:
            assert len(cfg_backend.image_refs) == 2
        finally:
            cfg_backend.close()

        # strict=True raises BackendQueryError when an image yields zero SBOM components.
        no_sbom_client = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: (
                    httpx.Response(
                        200,
                        headers={"Docker-Content-Digest": f"sha256:{'9' * 64}"},
                        json={"schemaVersion": 2},
                    )
                    if "/manifests/" in req.url.path
                    else httpx.Response(200, json={"manifests": []})
                )
            )
        )
        strict_backend = OciSbomBackend(
            images=("ghcr.io/org/empty:1.0",),
            strict=True,
            http_client=no_sbom_client,
        )
        try:
            with pytest.raises(BackendQueryError, match="No verifiable SBOM"):
                strict_backend.find_components((_requests_query(),))
        finally:
            no_sbom_client.close()

        # Oversized SBOM layer declares size > max_sbom_bytes -> BackendQueryError.
        huge_layer_digest = f"sha256:{'c' * 64}"
        huge_ref = json.dumps(
            {
                "schemaVersion": 2,
                "artifactType": "application/vnd.cyclonedx+json",
                "layers": [
                    {
                        "mediaType": "application/vnd.cyclonedx+json",
                        "digest": huge_layer_digest,
                        "size": 4096,
                    }
                ],
            }
        ).encode("utf-8")
        huge_ref_digest = f"sha256:{hashlib.sha256(huge_ref).hexdigest()}"
        huge_client = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: (
                    httpx.Response(
                        200,
                        headers={"Docker-Content-Digest": f"sha256:{'8' * 64}"},
                        json={"schemaVersion": 2},
                    )
                    if req.url.path.endswith("/manifests/1.0")
                    else httpx.Response(
                        200,
                        json={
                            "manifests": [
                                {
                                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                                    "digest": huge_ref_digest,
                                    "artifactType": "application/vnd.cyclonedx+json",
                                }
                            ]
                        },
                    )
                    if "/referrers/" in req.url.path
                    else httpx.Response(200, content=huge_ref)
                )
            )
        )
        bounded_backend = OciSbomBackend(
            images=("ghcr.io/org/huge:1.0",),
            max_sbom_bytes=1024,
            http_client=huge_client,
        )
        try:
            with pytest.raises(BackendQueryError, match="limit 1024"):
                bounded_backend.find_components((_requests_query(),))
        finally:
            huge_client.close()

    def test_dsse_depth_limit_auth_realm_pinning_and_blob_redirect_ssrf(self) -> None:
        # 1) Nested DSSE envelope depth > 5 fails closed with BackendQueryError.
        nested = _cdx_bytes(("requests", "2.30.0", "pkg:pypi/requests@2.30.0"))
        for _ in range(7):
            nested = json.dumps(
                {
                    "payloadType": "application/vnd.in-toto+json",
                    "payload": base64.b64encode(nested).decode("ascii"),
                    "signatures": [],
                }
            ).encode("utf-8")
        deep_digest = f"sha256:{hashlib.sha256(nested).hexdigest()}"
        deep_ref = json.dumps(
            {
                "schemaVersion": 2,
                "artifactType": "application/vnd.dsse.envelope.v1+json",
                "layers": [
                    {
                        "mediaType": "application/vnd.dsse.envelope.v1+json",
                        "digest": deep_digest,
                    }
                ],
            }
        ).encode("utf-8")
        deep_ref_digest = f"sha256:{hashlib.sha256(deep_ref).hexdigest()}"

        def _deep_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v2/org/deep/manifests/1.0":
                return httpx.Response(
                    200,
                    headers={"Docker-Content-Digest": f"sha256:{'1' * 64}"},
                    json={"schemaVersion": 2},
                )
            if request.url.path.startswith("/v2/org/deep/referrers/"):
                return httpx.Response(
                    200,
                    json={
                        "manifests": [
                            {
                                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                                "digest": deep_ref_digest,
                                "artifactType": "application/vnd.dsse.envelope.v1+json",
                            }
                        ]
                    },
                )
            if request.url.path.endswith(deep_ref_digest):
                return httpx.Response(200, content=deep_ref)
            if request.url.path.endswith(deep_digest):
                return httpx.Response(200, content=nested)
            return httpx.Response(404)

        deep_client = httpx.Client(transport=httpx.MockTransport(_deep_handler))
        deep_backend = OciSbomBackend(images=("ghcr.io/org/deep:1.0",), http_client=deep_client)
        try:
            with pytest.raises(BackendQueryError, match="depth limit"):
                deep_backend.find_components((_requests_query(),))
        finally:
            deep_client.close()

        # 2) Untrusted 401 WWW-Authenticate realm cannot steal registry Basic Auth credentials.
        sent_to_evil = False

        def _evil_realm_handler(request: httpx.Request) -> httpx.Response:
            nonlocal sent_to_evil
            if request.url.host == "evil-auth.example":
                sent_to_evil = True
                return httpx.Response(200, json={"token": "stolen"})
            return httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": 'Bearer realm="https://evil-auth.example/token",service="s"'
                },
            )

        realm_client = httpx.Client(transport=httpx.MockTransport(_evil_realm_handler))
        realm_backend = OciSbomBackend(
            images=("ghcr.io/org/app:1.0",),
            username="robot",
            password=_cred("oci-secret"),
            http_client=realm_client,
        )
        try:
            with pytest.raises(BackendQueryError, match="untrusted auth realm"):
                realm_backend.find_components((_requests_query(),))
            assert sent_to_evil is False
        finally:
            realm_client.close()

        # 3) 3xx blob redirect to IMDS / private DNS fails closed before issuing GET.
        imds_called = False
        sbom_blob = _cdx_bytes(("requests", "2.30.0", "pkg:pypi/requests@2.30.0"))
        blob_digest = f"sha256:{hashlib.sha256(sbom_blob).hexdigest()}"
        ref_manifest = json.dumps(
            {
                "schemaVersion": 2,
                "artifactType": "application/vnd.cyclonedx+json",
                "layers": [{"mediaType": "application/vnd.cyclonedx+json", "digest": blob_digest}],
            }
        ).encode("utf-8")
        ref_digest = f"sha256:{hashlib.sha256(ref_manifest).hexdigest()}"

        def _ssrf_blob_handler(request: httpx.Request) -> httpx.Response:
            nonlocal imds_called
            if request.url.host in {"169.254.169.254", "internal.cdn"}:
                imds_called = True
                return httpx.Response(200, content=sbom_blob)
            if request.url.path == "/v2/org/ssrf/manifests/1.0":
                return httpx.Response(
                    200,
                    headers={"Docker-Content-Digest": f"sha256:{'2' * 64}"},
                    json={"schemaVersion": 2},
                )
            if request.url.path.startswith("/v2/org/ssrf/referrers/"):
                return httpx.Response(
                    200,
                    json={
                        "manifests": [
                            {
                                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                                "digest": ref_digest,
                                "artifactType": "application/vnd.cyclonedx+json",
                            }
                        ]
                    },
                )
            if request.url.path.endswith(ref_digest):
                return httpx.Response(200, content=ref_manifest)
            if request.url.path.endswith(blob_digest):
                return httpx.Response(
                    307,
                    headers={"Location": "https://169.254.169.254/latest/meta-data/"},
                )
            return httpx.Response(404)

        ssrf_client = httpx.Client(transport=httpx.MockTransport(_ssrf_blob_handler))
        ssrf_backend = OciSbomBackend(images=("ghcr.io/org/ssrf:1.0",), http_client=ssrf_client)
        try:
            with pytest.raises(BackendQueryError, match="SSRF"):
                ssrf_backend.find_components((_requests_query(),))
            assert imds_called is False
        finally:
            ssrf_client.close()


# ---------------------------------------------------------------------------
# 4. Kubernetes Trivy Operator SbomReport Backend
# ---------------------------------------------------------------------------


class TestK8sSbomBackend:
    def test_conformance_and_registry_discovery(self) -> None:
        assert "k8s_sbom" in BackendRegistry().list_backends()

        def _handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == (
                "/apis/aquasecurity.github.io/v1alpha1/namespaces/prod/sbomreports"
            )
            assert request.headers["Authorization"] == f"Bearer {_cred('k8s')}"
            return httpx.Response(
                200,
                json={
                    "apiVersion": "aquasecurity.github.io/v1alpha1",
                    "kind": "SbomReportList",
                    "metadata": {},
                    "items": [
                        {
                            "metadata": {
                                "name": "deploy-payments-app",
                                "namespace": "prod",
                                "uid": "uid-1",
                                "labels": {
                                    "trivy-operator.resource.kind": "ReplicaSet",
                                    "trivy-operator.resource.name": "payments-7d9",
                                    "trivy-operator.container.name": "app",
                                },
                            },
                            "report": {
                                "registry": {"server": "ghcr.io"},
                                "artifact": {"repository": "acme/payments", "tag": "1.0.0"},
                                "components": json.loads(
                                    _cdx_bytes(("requests", "2.30.0", "pkg:pypi/requests@2.30.0"))
                                ),
                            },
                        }
                    ],
                },
            )

        client = httpx.Client(transport=httpx.MockTransport(_handler))
        backend = K8sSbomBackend(
            api_server="https://k8s.internal:6443",
            cluster_name="prod-eu",
            namespace="prod",
            bearer_token=_cred("k8s"),
            http_client=client,
        )
        try:
            case = build_default_conformance_case(backend_name="k8s_sbom")
            matches = assert_backend_conformance(backend, case)
            assert len(matches) == 1
            assert matches[0].asset is not None
            assert matches[0].asset.asset_id == "k8s://prod-eu/prod/sbomreport/deploy-payments-app"
            assert matches[0].asset.asset_type == "k8s_workload"
            assert matches[0].asset.metadata["resource_kind"] == "ReplicaSet"
            assert matches[0].asset.metadata["image"] == "ghcr.io/acme/payments:1.0.0"
        finally:
            client.close()

    def test_pagination_continue_cluster_reports_and_max_pages_guard(self) -> None:
        visited: list[tuple[str, str | None]] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            cont = request.url.params.get("continue")
            visited.append((request.url.path, cont))
            if request.url.path == "/apis/aquasecurity.github.io/v1alpha1/sbomreports":
                if cont is None:
                    return httpx.Response(
                        200,
                        json={
                            "metadata": {"continue": "page-2-token"},
                            "items": [
                                {
                                    "metadata": {"name": "pod-a", "namespace": "ns-a"},
                                    "report": {
                                        "components": [
                                            {
                                                "name": "requests",
                                                "version": "2.29.0",
                                                "purl": "pkg:pypi/requests@2.29.0",
                                            }
                                        ]
                                    },
                                }
                            ],
                        },
                    )
                return httpx.Response(
                    200,
                    json={
                        "metadata": {},
                        "items": [
                            {
                                "metadata": {"name": "pod-b", "namespace": "ns-b"},
                                "report": {
                                    "components": json.loads(
                                        _cdx_bytes(
                                            ("requests", "2.30.0", "pkg:pypi/requests@2.30.0")
                                        )
                                    )
                                },
                            }
                        ],
                    },
                )
            if request.url.path == "/apis/aquasecurity.github.io/v1alpha1/clustersbomreports":
                return httpx.Response(
                    200,
                    json={
                        "metadata": {},
                        "items": [
                            {
                                "metadata": {"name": "node-coredns"},
                                "report": {
                                    "components": json.loads(
                                        _cdx_bytes(
                                            ("requests", "2.28.0", "pkg:pypi/requests@2.28.0")
                                        )
                                    )
                                },
                            }
                        ],
                    },
                )
            return httpx.Response(404)

        client = httpx.Client(transport=httpx.MockTransport(_handler))
        backend = K8sSbomBackend(
            api_server="https://k8s.internal",
            include_cluster_reports=True,
            bearer_token=_cred("k8s"),
            http_client=client,
        )
        try:
            found = backend.find_components((_requests_query(),))
            assert len(found) == 3
            assert {comp.asset.asset_id for comp in found} == {
                "k8s://default/ns-a/sbomreport/pod-a",
                "k8s://default/ns-b/sbomreport/pod-b",
                "k8s://default/_cluster/sbomreport/node-coredns",
            }
            assert (
                "/apis/aquasecurity.github.io/v1alpha1/sbomreports",
                "page-2-token",
            ) in visited
            assert (
                "/apis/aquasecurity.github.io/v1alpha1/clustersbomreports",
                None,
            ) in visited
        finally:
            client.close()

        # Fail closed when continue token persists past max_pages.
        loop_client = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: httpx.Response(
                    200,
                    json={"metadata": {"continue": "still-more"}, "items": []},
                )
            )
        )
        loop_backend = K8sSbomBackend(
            api_server="https://k8s.internal",
            max_pages=2,
            http_client=loop_client,
        )
        try:
            with pytest.raises(BackendQueryError, match="max_pages=2"):
                loop_backend.find_components((_requests_query(),))
        finally:
            loop_client.close()

    def test_kubeconfig_tls_in_cluster_and_exec_rejection(self, tmp_path: Path) -> None:
        ca_b64 = base64.b64encode(Path(certifi.where()).read_bytes()).decode("ascii")
        k8s_secret = _cred("kc")
        kc_path = tmp_path / "kubeconfig.yaml"
        kc_path.write_text(
            yaml.safe_dump(
                {
                    "apiVersion": "v1",
                    "kind": "Config",
                    "current-context": "prod-ctx",
                    "clusters": [
                        {
                            "name": "prod-cluster",
                            "cluster": {
                                "server": "https://api.prod.k8s.internal:6443",
                                "certificate-authority-data": ca_b64,
                            },
                        }
                    ],
                    "contexts": [
                        {
                            "name": "prod-ctx",
                            "context": {"cluster": "prod-cluster", "user": "prod-reader"},
                        }
                    ],
                    "users": [
                        {"name": "prod-reader", "user": {"token": k8s_secret}},
                    ],
                }
            ),
            encoding="utf-8",
        )

        kc_backend = K8sSbomBackend(kubeconfig=kc_path, namespace="default")
        try:
            assert k8s_secret not in repr(kc_backend)
            assert "prod-cluster" in repr(kc_backend)
        finally:
            kc_backend.close()

        # Reject kubeconfig exec credential plugin (no arbitrary subprocess execution).
        exec_kc = tmp_path / "exec-kubeconfig.yaml"
        exec_kc.write_text(
            yaml.safe_dump(
                {
                    "apiVersion": "v1",
                    "kind": "Config",
                    "current-context": "eks",
                    "clusters": [{"name": "eks", "cluster": {"server": "https://eks.internal"}}],
                    "contexts": [{"name": "eks", "context": {"cluster": "eks", "user": "aws"}}],
                    "users": [{"name": "aws", "user": {"exec": {"command": "aws"}}}],
                }
            ),
            encoding="utf-8",
        )
        with pytest.raises(BackendConfigError, match="exec"):
            K8sSbomBackend(kubeconfig=exec_kc)

        # Reject insecure-skip-tls-verify unless verify_tls=False is explicitly set.
        insecure_kc = tmp_path / "insecure-kubeconfig.yaml"
        insecure_kc.write_text(
            yaml.safe_dump(
                {
                    "apiVersion": "v1",
                    "kind": "Config",
                    "current-context": "dev",
                    "clusters": [
                        {
                            "name": "dev",
                            "cluster": {
                                "server": "https://dev.internal",
                                "insecure-skip-tls-verify": True,
                            },
                        }
                    ],
                    "contexts": [{"name": "dev", "context": {"cluster": "dev"}}],
                }
            ),
            encoding="utf-8",
        )
        with pytest.raises(BackendConfigError, match="insecure-skip-tls-verify"):
            K8sSbomBackend(kubeconfig=insecure_kc)

        # Test in-cluster ServiceAccount discovery with IPv6 + trailing newline in tokenFile
        # plus wrapped multiline base64 CA PEM and verify_tls=False inline cert guard.
        sa_token_file = tmp_path / "sa-token"
        sa_token_file.write_text(_cred("sa") + "\r\n", encoding="utf-8")
        sa_ca_file = tmp_path / "ca.crt"
        sa_ca_file.write_bytes(Path(certifi.where()).read_bytes())

        sa_backend = K8sSbomBackend(
            in_cluster=True,
            serviceaccount_token_path=sa_token_file,
            serviceaccount_ca_path=sa_ca_file,
            env={
                "KUBERNETES_SERVICE_HOST": "fd00::1",
                "KUBERNETES_SERVICE_PORT": "443",
            },
        )
        try:
            assert "https://[fd00::1]:443" in repr(sa_backend)
        finally:
            sa_backend.close()

        wrapped_ca_b64 = "\n".join(ca_b64[i : i + 64] for i in range(0, len(ca_b64), 64))
        wrapped_kc = tmp_path / "wrapped-kubeconfig.yaml"
        wrapped_kc.write_text(
            yaml.safe_dump(
                {
                    "apiVersion": "v1",
                    "kind": "Config",
                    "current-context": "wrapped",
                    "clusters": [
                        {
                            "name": "wrapped-c",
                            "cluster": {
                                "server": "https://api.wrapped.k8s.internal",
                                "certificate-authority-data": wrapped_ca_b64,
                            },
                        }
                    ],
                    "contexts": [
                        {"name": "wrapped", "context": {"cluster": "wrapped-c", "user": "u"}}
                    ],
                    "users": [
                        {
                            "name": "u",
                            "user": {
                                "client-certificate-data": wrapped_ca_b64,
                                "client-key-data": wrapped_ca_b64,
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        with pytest.raises(BackendConfigError, match="client certificate"):
            K8sSbomBackend(kubeconfig=wrapped_kc, verify_tls=False)

        # Combining namespace="prod" + include_cluster_reports=True queries both endpoints.
        ns_and_cluster_paths: list[str] = []
        combo_client = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: (
                    ns_and_cluster_paths.append(req.url.path),
                    httpx.Response(200, json={"items": []}),
                )[1]
            )
        )
        combo_backend = K8sSbomBackend(
            api_server="https://k8s.internal",
            namespace="prod",
            include_cluster_reports=True,
            http_client=combo_client,
        )
        try:
            combo_backend.find_components((_requests_query(),))
            assert ns_and_cluster_paths == [
                "/apis/aquasecurity.github.io/v1alpha1/namespaces/prod/sbomreports",
                "/apis/aquasecurity.github.io/v1alpha1/clustersbomreports",
            ]
        finally:
            combo_client.close()

    def test_namespace_validation_and_http_error_mapping(self) -> None:
        for bad_ns in ("../kube-system", "UPPER", "-leading", "trailing-", "a" * 64):
            with pytest.raises(BackendConfigError, match="namespace"):
                K8sSbomBackend(
                    api_server="https://k8s.internal",
                    namespace=bad_ns,
                )

        for status_code in (302, 401, 403, 404, 429, 503):
            err_client = httpx.Client(
                transport=httpx.MockTransport(lambda req, code=status_code: httpx.Response(code))
            )
            backend = K8sSbomBackend(api_server="https://k8s.internal", http_client=err_client)
            try:
                with pytest.raises(BackendQueryError):
                    backend.find_components((_requests_query(),))
            finally:
                err_client.close()
