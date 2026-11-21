"""OCI Distribution v1.1 container registry SBOM and attestation inventory backend."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from zerobom.backends._http import (
    DEFAULT_API_TIMEOUT_SECONDS,
    DEFAULT_MAX_RESPONSE_BYTES,
    MAX_API_TIMEOUT_SECONDS,
    REDIRECT_STATUS_CODES,
    parse_bool_opt,
    parse_float_opt,
    parse_int_opt,
    parse_optional_str_opt,
    parse_str_list_opt,
    read_bounded_response,
    redact_url_for_error,
    reject_unknown_config_keys,
    resolve_tls_verify,
    validate_api_base_url,
    validate_bounded_int,
    validate_no_control_chars,
    validate_timeout_seconds,
)
from zerobom.backends.base import BackendConfigError, BackendQueryError
from zerobom.backends.sbom_parser import (
    MAX_CYCLONEDX_DEPTH,
    InMemoryComponentIndex,
    SbomParseError,
    clean_optional_str,
    is_cyclonedx_document,
    is_spdx_document,
    parse_sbom_bytes,
)
from zerobom.ingest.fetcher import DnsResolver, default_dns_resolver, is_public_ip
from zerobom.models import InventoryComponent, PackageQuery

_SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA512_DIGEST_RE = re.compile(r"^sha512:[0-9a-f]{128}$")
_OCI_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
_OCI_REGISTRY_RE = re.compile(r"^[A-Za-z0-9.-]+(?::[0-9]{1,5})?$")
_OCI_REPO_SEGMENT_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$")
_AUTH_PARAM_RE = re.compile(r'([A-Za-z0-9_]+)="([^"\\]*)"')
_MAX_IMAGES = 100
_MAX_REFERRERS_PER_IMAGE = 20
_MAX_LAYERS_PER_REFERRER = 10
_MAX_MANIFESTS_PER_IMAGE = 4
_MAX_TOKEN_RESPONSE_BYTES = 256 * 1024
_MAX_DSSE_DEPTH = 5
_KNOWN_AUTH_HOSTS: dict[str, frozenset[str]] = {
    "registry-1.docker.io": frozenset({"auth.docker.io"}),
    "ghcr.io": frozenset({"ghcr.io", "token.actions.githubusercontent.com"}),
    "quay.io": frozenset({"quay.io"}),
    "gcr.io": frozenset({"gcr.io", "oauth2.googleapis.com"}),
}

_MANIFEST_ACCEPT_HEADER = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)
_INDEX_MEDIA_TYPES: frozenset[str] = frozenset(
    {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
)
_CYCLONEDX_MEDIA_TYPES: frozenset[str] = frozenset(
    {
        "application/vnd.cyclonedx+json",
        "application/vnd.cyclonedx.json",
        "application/vnd.cyclonedx",
    }
)
_SPDX_MEDIA_TYPES: frozenset[str] = frozenset(
    {
        "application/spdx+json",
        "application/vnd.spdx+json",
        "application/spdx",
    }
)
_ATTESTATION_MEDIA_TYPES: frozenset[str] = frozenset(
    {
        "application/vnd.in-toto+json",
        "application/vnd.dsse.envelope.v1+json",
    }
)
_DIRECT_SBOM_MEDIA_TYPES: frozenset[str] = _CYCLONEDX_MEDIA_TYPES | _SPDX_MEDIA_TYPES
_SUPPORTED_LAYER_MEDIA_TYPES: frozenset[str] = _DIRECT_SBOM_MEDIA_TYPES | _ATTESTATION_MEDIA_TYPES

_ALLOWED_CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "images",
        "username",
        "password",
        "bearer_token",
        "platform",
        "allowed_auth_hosts",
        "fallback_tag_schema",
        "allow_blob_redirects",
        "allow_private_redirects",
        "allow_insecure_http",
        "ca_bundle",
        "verify_tls",
        "timeout_seconds",
        "max_sbom_bytes",
        "strict",
    }
)


@dataclass(frozen=True)
class OciImageRef:
    """Parsed and validated OCI container image reference."""

    registry: str
    repository: str
    tag: str | None
    digest: str | None
    raw_reference: str


def _base_media_type(raw: Any) -> str:
    """Normalize a media type header or descriptor field by dropping optional parameters."""
    if not isinstance(raw, str):
        return ""
    return raw.split(";", 1)[0].strip().lower()


def _is_valid_digest(value: str) -> bool:
    """Return True if ``value`` is a supported lowercase SHA-256 or SHA-512 OCI digest."""
    return bool(_SHA256_DIGEST_RE.fullmatch(value) or _SHA512_DIGEST_RE.fullmatch(value))


def _verify_digest(payload: bytes, expected_digest: str, *, context: str) -> None:
    """Verify SHA-256/SHA-512 content digest using constant-time comparison."""
    algo, _, expected_hex = expected_digest.partition(":")
    if algo == "sha256" and _SHA256_DIGEST_RE.fullmatch(expected_digest):
        actual_hex = hashlib.sha256(payload).hexdigest()
    elif algo == "sha512" and _SHA512_DIGEST_RE.fullmatch(expected_digest):
        actual_hex = hashlib.sha512(payload).hexdigest()
    else:
        raise BackendQueryError(
            f"[oci_sbom] Unsupported or malformed OCI digest {expected_digest!r} for {context}."
        )
    if not hmac.compare_digest(actual_hex, expected_hex):
        raise BackendQueryError(
            f"[oci_sbom] Digest mismatch for {context}: expected {expected_digest}, "
            f"got {algo}:{actual_hex}."
        )


def parse_oci_image_ref(reference: str) -> OciImageRef:
    """Parse and validate an OCI container image reference string.

    Supports registries with ports (e.g., ``localhost:5000/app/svc:1.2.3``), digest-pinned
    references (e.g., ``ghcr.io/org/app@sha256:...``), and Docker Hub shorthand names
    (e.g., ``nginx:1.27`` -> ``registry-1.docker.io/library/nginx:1.27``).

    Args:
        reference: Raw container image reference string.

    Returns:
        Validated :class:`OciImageRef`.

    Raises:
        BackendConfigError: If the reference violates OCI syntax, digest/tag rules, or
            contains control characters, credentials, traversal segments, or URL schemes.
    """
    cleaned = validate_no_control_chars(reference, field_name="images", max_length=512)
    if any(ch.isspace() for ch in cleaned):
        raise BackendConfigError(f"Invalid OCI image reference {reference!r}: contains whitespace.")
    if "://" in cleaned or "\\" in cleaned or ".." in cleaned:
        raise BackendConfigError(
            f"Invalid OCI image reference {reference!r}: disallowed scheme or path sequence."
        )

    name_part = cleaned
    digest: str | None = None
    if "@" in cleaned:
        name_part, digest_part = cleaned.split("@", 1)
        if not name_part or "@" in digest_part or not _is_valid_digest(digest_part):
            raise BackendConfigError(
                f"Invalid OCI digest in image reference {reference!r}; expected sha256 or sha512."
            )
        digest = digest_part

    tag: str | None = None
    last_slash = name_part.rfind("/")
    colon_idx = name_part.find(":", last_slash + 1)
    if colon_idx != -1:
        tag = name_part[colon_idx + 1 :]
        name_part = name_part[:colon_idx]
        if not _OCI_TAG_RE.fullmatch(tag):
            raise BackendConfigError(f"Invalid OCI tag {tag!r} in image reference {reference!r}.")

    if tag is None and digest is None:
        raise BackendConfigError(
            f"OCI image reference {reference!r} must include a ':tag' or '@sha256:...' digest."
        )

    if "/" in name_part:
        first_seg, rest = name_part.split("/", 1)
        if "." in first_seg or ":" in first_seg or first_seg.lower() == "localhost":
            registry = first_seg.lower()
            repository = rest
        else:
            registry = "registry-1.docker.io"
            repository = name_part
    else:
        registry = "registry-1.docker.io"
        repository = f"library/{name_part}"

    if registry in {"docker.io", "index.docker.io"}:
        registry = "registry-1.docker.io"

    if not _OCI_REGISTRY_RE.fullmatch(registry):
        raise BackendConfigError(f"Invalid OCI registry host {registry!r} in {reference!r}.")
    if ":" in registry:
        _, port_str = registry.rsplit(":", 1)
        port = int(port_str)
        if not 1 <= port <= 65535:
            raise BackendConfigError(f"Invalid OCI registry port in {reference!r}.")

    if len(repository) > 256:
        raise BackendConfigError(f"OCI repository name exceeds 256 characters in {reference!r}.")
    repo_segments = repository.split("/")
    if (
        not repo_segments
        or len(repo_segments) > 16
        or any(not _OCI_REPO_SEGMENT_RE.fullmatch(seg) for seg in repo_segments)
    ):
        raise BackendConfigError(
            f"Invalid OCI repository path {repository!r} in image reference {reference!r}."
        )

    return OciImageRef(
        registry=registry,
        repository=repository,
        tag=tag,
        digest=digest,
        raw_reference=cleaned,
    )


def _fallback_referrers_tag(digest: str) -> str:
    """Return OCI 1.0 fallback referrers tag (``sha256-<hex>``)."""
    return digest.replace(":", "-", 1)


def _decode_manifest_json(body: bytes, *, context: str) -> dict[str, Any]:
    """Decode an OCI manifest or index JSON payload into a mapping."""
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BackendQueryError(f"[oci_sbom] Invalid JSON manifest for {context}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise BackendQueryError(
            f"[oci_sbom] OCI manifest root for {context} must be a JSON object."
        )
    return parsed


def _is_candidate_referrer(descriptor: Mapping[str, Any]) -> bool:
    """Return True if an OCI referrer descriptor could hold an SBOM or attestation."""
    artifact_type = _base_media_type(descriptor.get("artifactType"))
    media_type = _base_media_type(descriptor.get("mediaType"))
    annotations = descriptor.get("annotations")
    ann_type = (
        _base_media_type(annotations.get("org.opencontainers.artifact.type"))
        if isinstance(annotations, Mapping)
        else ""
    )

    for candidate in (artifact_type, ann_type):
        if candidate in _SUPPORTED_LAYER_MEDIA_TYPES:
            return True
        if any(marker in candidate for marker in ("cyclonedx", "spdx", "sbom", "in-toto", "dsse")):
            return True
        # Skip known unrelated artifact types (e.g., plain cosign signatures) unless in-toto/sbom.
        if candidate and any(skip in candidate for skip in ("sigstore", "simplesigning", "sarif")):
            return False

    return media_type in {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.artifact.manifest.v1+json",
    }


def _unwrap_sbom_payload(
    blob: bytes,
    *,
    max_sbom_bytes: int,
    context: str,
    _depth: int = 0,
) -> bytes | None:
    """Unwrap bounded DSSE or In-Toto attestation envelopes around CycloneDX/SPDX payloads."""
    if _depth > _MAX_DSSE_DEPTH:
        raise BackendQueryError(
            f"[oci_sbom] DSSE attestation nesting for {context} exceeds depth limit "
            f"{_MAX_DSSE_DEPTH}."
        )

    try:
        doc = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BackendQueryError(
            f"[oci_sbom] Malformed JSON SBOM/attestation blob for {context}: {exc}"
        ) from exc

    if not isinstance(doc, dict):
        return None

    if is_cyclonedx_document(doc) or is_spdx_document(doc):
        return blob

    # Unwrap DSSE envelope (`payloadType` + base64 `payload`) with pre-decode size guard.
    if isinstance(doc.get("payload"), str) and isinstance(doc.get("payloadType"), str):
        b64_payload = doc["payload"]
        if len(b64_payload) > (max_sbom_bytes * 4) // 3 + 16:
            raise BackendQueryError(
                f"[oci_sbom] DSSE attestation payload for {context} exceeds max_sbom_bytes."
            )
        try:
            decoded_bytes = base64.b64decode(b64_payload, validate=True)
        except ValueError as exc:
            raise BackendQueryError(
                f"[oci_sbom] Invalid base64 payload inside DSSE envelope for {context}: {exc}"
            ) from exc
        if len(decoded_bytes) > max_sbom_bytes:
            raise BackendQueryError(
                f"[oci_sbom] Decoded DSSE payload for {context} exceeds {max_sbom_bytes} bytes."
            )
        return _unwrap_sbom_payload(
            decoded_bytes,
            max_sbom_bytes=max_sbom_bytes,
            context=context,
            _depth=_depth + 1,
        )

    # Unwrap In-Toto Statement v0.1/v1 (`predicate` holding CycloneDX or SPDX document).
    stmt_type = doc.get("_type")
    predicate = doc.get("predicate")
    if isinstance(stmt_type, str) and stmt_type.startswith("https://in-toto.io/Statement"):
        if not isinstance(predicate, Mapping):
            return None
        pred_dict = dict(predicate)
        if is_cyclonedx_document(pred_dict) or is_spdx_document(pred_dict):
            return json.dumps(pred_dict).encode("utf-8")
        return None

    return None


class OciSbomBackend:
    """OCI Distribution v1.1 container image SBOM and attestation inventory backend."""

    def __init__(
        self,
        *,
        images: Sequence[str],
        username: str | None = None,
        password: str | None = None,
        bearer_token: str | None = None,
        platform: str | None = None,
        allowed_auth_hosts: Sequence[str] = (),
        fallback_tag_schema: bool = True,
        allow_blob_redirects: bool = True,
        allow_private_redirects: bool = False,
        allow_insecure_http: bool = False,
        ca_bundle: str | Path | None = None,
        verify_tls: bool = True,
        timeout_seconds: float = DEFAULT_API_TIMEOUT_SECONDS,
        max_sbom_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        strict: bool = False,
        dns_resolver: DnsResolver | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        """Initialize an OCI container registry SBOM inventory backend.

        Args:
            images: Container image references to scan for attached SBOMs/attestations.
            username: Optional registry username for HTTP Basic / Bearer token exchange.
            password: Optional registry password or PAT matching ``username``.
            bearer_token: Optional pre-minted registry Bearer token.
            platform: Optional multi-arch filter formatted as ``os/arch`` (e.g. ``linux/amd64``).
            allowed_auth_hosts: Optional explicit third-party bearer auth realm host allowlist.
            fallback_tag_schema: Fall back to OCI 1.0 ``sha256-<hex>`` tags on 404 referrers.
            allow_blob_redirects: Follow one validated HTTPS redirect on ``/blobs/`` requests
                with authorization headers stripped.
            allow_private_redirects: Explicit opt-in to permit private/loopback redirect or realm
                targets for internal registries.
            allow_insecure_http: Explicit opt-in to permit ``http://`` registries/token realms.
            ca_bundle: Optional PEM CA bundle path for private internal registries.
            verify_tls: Enable TLS certificate verification.
            timeout_seconds: HTTP request timeout in ``0.5..120.0`` seconds.
            max_sbom_bytes: Maximum SBOM/attestation blob size permitted per layer.
            strict: Raise :class:`BackendQueryError` if an image yields zero SBOM components.
            dns_resolver: Optional DNS resolver callable for offline SSRF testing.
            http_client: Optional externally managed :class:`httpx.Client` (e.g., in tests).

        Raises:
            BackendConfigError: If image references, credentials, platform, TLS, or bounds fail.
        """
        if not isinstance(fallback_tag_schema, bool):
            raise BackendConfigError("Configuration option 'fallback_tag_schema' must be a bool.")
        if not isinstance(allow_blob_redirects, bool):
            raise BackendConfigError("Configuration option 'allow_blob_redirects' must be a bool.")
        if not isinstance(allow_private_redirects, bool):
            raise BackendConfigError(
                "Configuration option 'allow_private_redirects' must be a bool."
            )
        if not isinstance(allow_insecure_http, bool):
            raise BackendConfigError("Configuration option 'allow_insecure_http' must be a bool.")
        if not isinstance(verify_tls, bool):
            raise BackendConfigError("Configuration option 'verify_tls' must be a bool.")
        if not isinstance(strict, bool):
            raise BackendConfigError("Configuration option 'strict' must be a bool.")

        if isinstance(images, (str, bytes)) or not isinstance(images, Sequence):
            raise BackendConfigError(
                "Configuration option 'images' must be a sequence of image references."
            )
        if not images:
            raise BackendConfigError("OciSbomBackend requires at least one image reference.")
        if len(images) > _MAX_IMAGES:
            raise BackendConfigError(f"OciSbomBackend supports at most {_MAX_IMAGES} images.")

        parsed_refs: list[OciImageRef] = [parse_oci_image_ref(ref) for ref in images]
        self._image_refs: tuple[OciImageRef, ...] = tuple(parsed_refs)

        if (username is None) != (password is None):
            raise BackendConfigError("Both 'username' and 'password' must be provided together.")
        if bearer_token is not None and username is not None:
            raise BackendConfigError("Specify either 'bearer_token' or 'username'/'password'.")

        self._username = (
            validate_no_control_chars(username, field_name="username", max_length=512)
            if username is not None
            else None
        )
        self._password = (
            validate_no_control_chars(password, field_name="password", max_length=4096)
            if password is not None
            else None
        )
        self._bearer_token = (
            validate_no_control_chars(bearer_token, field_name="bearer_token", max_length=8192)
            if bearer_token is not None
            else None
        )

        self._platform_os: str | None = None
        self._platform_arch: str | None = None
        self._platform: str | None = None
        if platform is not None:
            cleaned_platform = validate_no_control_chars(
                platform, field_name="platform", max_length=64
            )
            os_part, sep, arch_part = cleaned_platform.partition("/")
            if not sep or not os_part or not arch_part or "/" in arch_part:
                raise BackendConfigError(
                    "Configuration option 'platform' must be formatted as '<os>/<arch>'."
                )
            self._platform_os = os_part.lower()
            self._platform_arch = arch_part.lower()
            self._platform = f"{self._platform_os}/{self._platform_arch}"

        self._timeout_seconds = validate_timeout_seconds(timeout_seconds)
        self._max_sbom_bytes = validate_bounded_int(
            max_sbom_bytes,
            field_name="max_sbom_bytes",
            min_value=1024,
            max_value=100 * 1024 * 1024,
        )

        self._allowed_auth_hosts: frozenset[str] = frozenset(
            validate_no_control_chars(host, field_name="allowed_auth_hosts", max_length=255)
            .lower()
            .rsplit(":", 1)[0]
            for host in allowed_auth_hosts
            if isinstance(host, str) and host.strip()
        )
        self._fallback_tag_schema = fallback_tag_schema
        self._allow_blob_redirects = allow_blob_redirects
        self._allow_private_redirects = allow_private_redirects
        self._allow_insecure_http = allow_insecure_http
        self._strict = strict
        self._scheme = "http" if allow_insecure_http else "https"
        self._dns_resolver = dns_resolver

        self._scoped_tokens: dict[tuple[str, str], str] = {}
        self._index: InMemoryComponentIndex | None = None

        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            verify_arg = resolve_tls_verify(verify_tls=verify_tls, ca_bundle=ca_bundle)
            self._client = httpx.Client(
                timeout=self._timeout_seconds,
                verify=verify_arg,
                follow_redirects=False,
                trust_env=False,
            )
            self._owns_client = True

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> OciSbomBackend:
        """Instantiate :class:`OciSbomBackend` from CLI options or YAML/JSON config.

        Environment variable fallbacks: ``ZEROBOM_OCI_TOKEN``, ``ZEROBOM_OCI_USERNAME``,
        and ``ZEROBOM_OCI_PASSWORD``.
        """
        reject_unknown_config_keys(config, _ALLOWED_CONFIG_KEYS, backend_name="oci_sbom")

        images = parse_str_list_opt(config, "images", max_items=_MAX_IMAGES, max_item_length=512)
        if not images:
            raise BackendConfigError("OciSbomBackend requires non-empty 'images' configuration.")

        username = parse_optional_str_opt(
            config, "username", env_var="ZEROBOM_OCI_USERNAME", max_length=512
        )
        password = parse_optional_str_opt(
            config, "password", env_var="ZEROBOM_OCI_PASSWORD", max_length=4096
        )
        bearer_token = parse_optional_str_opt(
            config, "bearer_token", env_var="ZEROBOM_OCI_TOKEN", max_length=8192
        )
        if "bearer_token" in config and "username" not in config and "password" not in config:
            username = None
            password = None
        elif (
            "bearer_token" not in config
            and ("username" in config or "password" in config)
            and username is not None
            and password is not None
        ):
            # Explicit username/password in config overrides stale ZEROBOM_OCI_TOKEN env var.
            bearer_token = None

        return cls(
            images=images,
            username=username,
            password=password,
            bearer_token=bearer_token,
            platform=parse_optional_str_opt(config, "platform", max_length=64),
            allowed_auth_hosts=parse_str_list_opt(
                config, "allowed_auth_hosts", max_items=20, max_item_length=255
            ),
            fallback_tag_schema=parse_bool_opt(config, "fallback_tag_schema", default=True),
            allow_blob_redirects=parse_bool_opt(config, "allow_blob_redirects", default=True),
            allow_private_redirects=parse_bool_opt(
                config, "allow_private_redirects", default=False
            ),
            allow_insecure_http=parse_bool_opt(config, "allow_insecure_http", default=False),
            ca_bundle=parse_optional_str_opt(config, "ca_bundle", max_length=2048),
            verify_tls=parse_bool_opt(config, "verify_tls", default=True),
            timeout_seconds=parse_float_opt(
                config,
                "timeout_seconds",
                default=DEFAULT_API_TIMEOUT_SECONDS,
                min_value=0.5,
                max_value=MAX_API_TIMEOUT_SECONDS,
            ),
            max_sbom_bytes=parse_int_opt(
                config,
                "max_sbom_bytes",
                default=DEFAULT_MAX_RESPONSE_BYTES,
                min_value=1024,
                max_value=100 * 1024 * 1024,
            ),
            strict=parse_bool_opt(config, "strict", default=False),
        )

    @property
    def name(self) -> str:
        """Registered backend plugin identifier (``"oci_sbom"``)."""
        return "oci_sbom"

    @property
    def image_refs(self) -> tuple[OciImageRef, ...]:
        """Configured OCI image references."""
        return self._image_refs

    def close(self) -> None:
        """Close the internally managed HTTP client connection pool."""
        if self._owns_client:
            self._client.close()

    def __repr__(self) -> str:
        """Return a redacted representation that never leaks registry secrets."""
        return (
            f"OciSbomBackend(images={len(self._image_refs)}, "
            f"platform={self._platform!r}, strict={self._strict})"
        )

    def load(self) -> int:
        """Fetch and index SBOMs/attestations for all configured container images."""
        index = InMemoryComponentIndex()
        for ref in self._image_refs:
            components = self._load_image_components(ref)
            if self._strict and not components:
                raise BackendQueryError(
                    f"[{self.name}] No verifiable SBOM components found for image "
                    f"{ref.raw_reference}."
                )
            index.add_components(components)
        self._index = index
        return len(index.components)

    def find_components(self, queries: Sequence[PackageQuery]) -> tuple[InventoryComponent, ...]:
        """Search indexed OCI image SBOM components for candidate package matches.

        Args:
            queries: Canonical package descriptors built from an OSV advisory.

        Returns:
            Matching :class:`InventoryComponent` records bound to each ``oci://`` image asset.
        """
        if not queries:
            return ()
        if self._index is None:
            self.load()
        if self._index is None:
            return ()
        return self._index.find_components(queries)

    def _base_v2_url(self, ref: OciImageRef) -> str:
        """Return validated ``scheme://registry/v2/repo`` root URL."""
        encoded_repo = "/".join(quote(seg, safe="") for seg in ref.repository.split("/"))
        return f"{self._scheme}://{ref.registry}/v2/{encoded_repo}"

    def _registry_get(
        self,
        ref: OciImageRef,
        url: str,
        *,
        accept: str,
        max_bytes: int,
        params: Mapping[str, str] | None = None,
    ) -> tuple[int, httpx.Headers, bytes]:
        """Execute a registry GET request with one-shot OCI Bearer challenge handling."""
        headers = {"Accept": accept}
        scope_key = (ref.registry, ref.repository)
        cached_cred = self._bearer_token or self._scoped_tokens.get(scope_key)
        auth_pair: tuple[str, str] | None = None
        if cached_cred is not None:
            headers["Authorization"] = f"Bearer {cached_cred}"
        elif self._username is not None and self._password is not None:
            auth_pair = (self._username, self._password)

        status, resp_headers, body = read_bounded_response(
            self._client,
            "GET",
            url,
            max_bytes=max_bytes,
            params=params,
            headers=headers,
            auth=auth_pair,
            backend_name=self.name,
        )

        if status != 401 or self._bearer_token is not None:
            return status, resp_headers, body

        www_auth = resp_headers.get("www-authenticate")
        if www_auth is None or not www_auth.lower().startswith("bearer "):
            return status, resp_headers, body

        new_cred = self._exchange_bearer_token(ref, www_auth)
        self._scoped_tokens[scope_key] = new_cred
        retry_headers = {"Accept": accept, "Authorization": f"Bearer {new_cred}"}
        return read_bounded_response(
            self._client,
            "GET",
            url,
            max_bytes=max_bytes,
            params=params,
            headers=retry_headers,
            backend_name=self.name,
        )

    def _is_trusted_auth_realm(self, registry: str, realm_host: str) -> bool:
        """Return ``True`` if ``realm_host`` is an authorized auth realm for ``registry``."""
        reg_host = registry.rsplit(":", 1)[0].lower()
        realm = realm_host.lower()
        if realm == reg_host or realm.endswith(f".{reg_host}"):
            return True
        if realm in self._allowed_auth_hosts:
            return True
        if realm in _KNOWN_AUTH_HOSTS.get(reg_host, ()):
            return True
        return reg_host.endswith(".pkg.dev") and realm in {"oauth2.googleapis.com", reg_host}

    def _validate_outbound_target(
        self,
        url: str,
        *,
        registry_host: str,
        field_name: str,
    ) -> str:
        """Validate a dynamic OCI realm or blob-redirect URL against SSRF targets."""
        try:
            validated = validate_api_base_url(
                url,
                allow_insecure_http=self._allow_insecure_http,
                field_name=field_name,
                allow_query=True,
            )
        except BackendConfigError as exc:
            raise BackendQueryError(f"[{self.name}] {exc}") from exc

        parsed = urlsplit(validated)
        hostname = (parsed.hostname or "").lower()
        scheme = parsed.scheme.lower()
        reg_host = registry_host.rsplit(":", 1)[0].lower()

        if self._allow_private_redirects:
            return validated

        # Always block cloud IMDS/link-local literals even when hitting private registries.
        try:
            ip_obj = ipaddress.ip_address(hostname)
        except ValueError:
            ip_obj = None

        if ip_obj is not None and (
            ip_obj.is_link_local or (hostname != reg_host and not is_public_ip(hostname))
        ):
            raise BackendQueryError(
                f"[{self.name}] Blocked SSRF {field_name} literal IP target {hostname!r}."
            )

        if hostname != reg_host and (hostname == "localhost" or hostname.endswith(".local")):
            raise BackendQueryError(
                f"[{self.name}] Blocked local/internal {field_name} host {hostname!r}."
            )

        resolver = self._dns_resolver or (default_dns_resolver if self._owns_client else None)
        if resolver is not None and hostname != reg_host and ip_obj is None:
            port = parsed.port or (443 if scheme == "https" else 80)
            try:
                resolved_ips = resolver(hostname, port)
            except Exception as exc:
                raise BackendQueryError(
                    f"[{self.name}] DNS resolution failed for {field_name} {hostname!r}: {exc}"
                ) from exc
            if not resolved_ips or any(not is_public_ip(ip_val) for ip_val in resolved_ips):
                raise BackendQueryError(
                    f"[{self.name}] Blocked SSRF {field_name}: {hostname!r} resolved to a "
                    "non-public IP address."
                )

        return validated

    def _exchange_bearer_token(self, ref: OciImageRef, www_authenticate: str) -> str:
        """Parse an OCI ``WWW-Authenticate: Bearer`` header and retrieve a scoped token."""
        if len(www_authenticate) > 4096:
            raise BackendQueryError(f"[{self.name}] Overly long WWW-Authenticate header.")

        challenge_params: dict[str, str] = {}
        for match in _AUTH_PARAM_RE.finditer(www_authenticate):
            challenge_params[match.group(1).lower()] = match.group(2)

        raw_realm = challenge_params.get("realm")
        if not raw_realm:
            raise BackendQueryError(
                f"[{self.name}] Registry 401 Bearer challenge is missing 'realm'."
            )
        realm_url = self._validate_outbound_target(
            raw_realm,
            registry_host=ref.registry,
            field_name="www_authenticate_realm",
        )
        realm_host = (urlsplit(realm_url).hostname or "").lower()

        query_params: dict[str, str] = {}
        for param_name in ("service", "scope"):
            param_val = challenge_params.get(param_name)
            if param_val:
                if any(ord(ch) < 32 or ord(ch) == 127 for ch in param_val):
                    raise BackendQueryError(
                        f"[{self.name}] Control characters in WWW-Authenticate {param_name!r}."
                    )
                query_params[param_name] = param_val

        basic_auth = (
            (self._username, self._password)
            if self._username is not None and self._password is not None
            else None
        )
        if basic_auth is not None and not self._is_trusted_auth_realm(ref.registry, realm_host):
            raise BackendQueryError(
                f"[{self.name}] Refused to send registry credentials to untrusted auth realm host "
                f"{realm_host!r} for registry {ref.registry!r} "
                "(configure allowed_auth_hosts if intentional)."
            )

        status, _, body = read_bounded_response(
            self._client,
            "GET",
            realm_url,
            max_bytes=_MAX_TOKEN_RESPONSE_BYTES,
            params=query_params or None,
            headers={"Accept": "application/json"},
            auth=basic_auth,
            backend_name=self.name,
        )
        safe_realm = redact_url_for_error(realm_url)
        if status in REDIRECT_STATUS_CODES:
            raise BackendQueryError(
                f"[{self.name}] Unexpected redirect ({status}) from auth realm {safe_realm}."
            )
        if status != 200:
            raise BackendQueryError(
                f"[{self.name}] Registry token exchange at {safe_realm} failed with "
                f"status {status}."
            )

        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise BackendQueryError(
                f"[{self.name}] Invalid JSON token response from {realm_url}: {exc}"
            ) from exc

        if not isinstance(payload, dict):
            raise BackendQueryError(
                f"[{self.name}] Token endpoint {realm_url} returned non-object."
            )

        raw_cred = payload.get("token") or payload.get("access_token")
        try:
            return validate_no_control_chars(
                raw_cred,
                field_name="registry_bearer_token",
                max_length=8192,
            )
        except BackendConfigError as exc:
            raise BackendQueryError(
                f"[{self.name}] Token endpoint {realm_url} did not return a valid token."
            ) from exc

    def _fetch_manifest(
        self,
        ref: OciImageRef,
        reference: str,
        *,
        allow_not_found: bool = False,
    ) -> tuple[str, dict[str, Any]] | None:
        """Fetch an OCI manifest or index JSON and return ``(resolved_digest, payload)``."""
        url = f"{self._base_v2_url(ref)}/manifests/{quote(reference, safe=':')}"
        status, headers, body = self._registry_get(
            ref,
            url,
            accept=_MANIFEST_ACCEPT_HEADER,
            max_bytes=self._max_response_bytes_for_manifest(),
        )
        if status == 404 and allow_not_found:
            return None
        if status in REDIRECT_STATUS_CODES:
            raise BackendQueryError(
                f"[{self.name}] Manifest redirect ({status}) refused for {ref.raw_reference}."
            )
        if status in (401, 403):
            raise BackendQueryError(
                f"[{self.name}] Registry auth failed ({status}) fetching manifest for "
                f"{ref.raw_reference}."
            )
        if status != 200:
            raise BackendQueryError(
                f"[{self.name}] Manifest fetch failed ({status}) for "
                f"{ref.raw_reference} ({reference})."
            )

        header_digest = clean_optional_str(headers.get("docker-content-digest"))
        computed_digest = f"sha256:{hashlib.sha256(body).hexdigest()}"
        resolved_digest = (
            header_digest if header_digest and _is_valid_digest(header_digest) else computed_digest
        )
        if _is_valid_digest(reference):
            _verify_digest(body, reference, context=f"{ref.raw_reference}@{reference}")
            resolved_digest = reference

        manifest = _decode_manifest_json(body, context=f"{ref.raw_reference} ({reference})")
        return resolved_digest, manifest

    def _max_response_bytes_for_manifest(self) -> int:
        """Keep manifest/index reads strictly bounded at <= 4 MiB."""
        return min(self._max_sbom_bytes, 4 * 1024 * 1024)

    def _fetch_referrers(self, ref: OciImageRef, subject_digest: str) -> list[dict[str, Any]]:
        """Query OCI v1.1 ``/referrers/`` API, with optional OCI 1.0 fallback tag lookup."""
        referrers_url = f"{self._base_v2_url(ref)}/referrers/{quote(subject_digest, safe=':')}"
        status, _, body = self._registry_get(
            ref,
            referrers_url,
            accept="application/vnd.oci.image.index.v1+json",
            max_bytes=self._max_response_bytes_for_manifest(),
        )
        if status in REDIRECT_STATUS_CODES:
            raise BackendQueryError(
                f"[{self.name}] Unexpected redirect ({status}) from OCI referrers API."
            )
        if status in (401, 403):
            raise BackendQueryError(
                f"[{self.name}] Authentication failed ({status}) on OCI referrers API."
            )
        if status == 200:
            index_doc = _decode_manifest_json(body, context=f"referrers:{subject_digest}")
            raw_manifests = index_doc.get("manifests")
            if isinstance(raw_manifests, list):
                return [item for item in raw_manifests if isinstance(item, dict)]
            return []

        if status != 404 or not self._fallback_tag_schema:
            raise BackendQueryError(
                f"[{self.name}] OCI referrers lookup failed ({status}) for {subject_digest}."
            )

        fallback_manifest = self._fetch_manifest(
            ref,
            _fallback_referrers_tag(subject_digest),
            allow_not_found=True,
        )
        if fallback_manifest is None:
            return []
        _, doc = fallback_manifest
        raw_manifests = doc.get("manifests")
        if isinstance(raw_manifests, list):
            return [item for item in raw_manifests if isinstance(item, dict)]
        return []

    def _fetch_blob(self, ref: OciImageRef, blob_digest: str) -> bytes:
        """Download an OCI blob with verified digest and credential-stripped redirect handling."""
        blob_url = f"{self._base_v2_url(ref)}/blobs/{quote(blob_digest, safe=':')}"
        status, headers, body = self._registry_get(
            ref,
            blob_url,
            accept="*/*",
            max_bytes=self._max_sbom_bytes,
        )

        if status in REDIRECT_STATUS_CODES:
            if not self._allow_blob_redirects:
                raise BackendQueryError(
                    f"[{self.name}] Blob redirect ({status}) disabled for {blob_digest}."
                )
            raw_location = headers.get("location")
            if not raw_location:
                raise BackendQueryError(
                    f"[{self.name}] Blob redirect ({status}) missing Location header."
                )
            redirect_url = self._validate_outbound_target(
                raw_location,
                registry_host=ref.registry,
                field_name="blob_redirect_location",
            )
            # Never forward registry credentials to third-party blob storage redirect targets.
            status, _, body = read_bounded_response(
                self._client,
                "GET",
                redirect_url,
                max_bytes=self._max_sbom_bytes,
                headers={"Accept": "*/*"},
                backend_name=self.name,
                redact_url_path=True,
            )
            if status in REDIRECT_STATUS_CODES:
                raise BackendQueryError(
                    f"[{self.name}] Nested blob redirect ({status}) refused from {redirect_url}."
                )

        if status in (401, 403):
            raise BackendQueryError(
                f"[{self.name}] Authentication failed ({status}) downloading blob {blob_digest}."
            )
        if status != 200:
            raise BackendQueryError(
                f"[{self.name}] Blob download failed ({status}) for {blob_digest}."
            )

        _verify_digest(body, blob_digest, context=f"{ref.raw_reference} blob {blob_digest}")
        return body

    def _load_image_components(self, ref: OciImageRef) -> tuple[InventoryComponent, ...]:
        """Resolve an image manifest, inspect referrers/attestations, and parse SBOM layers."""
        target_reference = ref.digest or ref.tag
        if target_reference is None:
            return ()

        fetched = self._fetch_manifest(ref, target_reference)
        if fetched is None:
            return ()
        root_digest, root_manifest = fetched

        subject_digests: list[str] = [root_digest]
        direct_manifests_to_inspect: list[tuple[str, str]] = []

        if self._is_index_manifest(root_manifest):
            child_digests, att_digests = self._select_index_targets(root_manifest)
            for child_digest in child_digests:
                if child_digest not in subject_digests:
                    subject_digests.append(child_digest)
            direct_manifests_to_inspect.extend(
                (att_digest, "application/vnd.in-toto+json") for att_digest in att_digests
            )

        components: list[InventoryComponent] = []
        inspected_referrers: set[str] = set()

        for att_digest, att_type in direct_manifests_to_inspect[:_MAX_REFERRERS_PER_IMAGE]:
            inspected_referrers.add(att_digest)
            components.extend(
                self._extract_components_from_referrer_manifest(
                    ref,
                    subject_digest=root_digest,
                    referrer_digest=att_digest,
                    artifact_type=att_type,
                )
            )

        for subject_digest in subject_digests:
            descriptors = self._fetch_referrers(ref, subject_digest)
            for desc in descriptors[:_MAX_REFERRERS_PER_IMAGE]:
                desc_digest = clean_optional_str(desc.get("digest"))
                if (
                    desc_digest is None
                    or not _is_valid_digest(desc_digest)
                    or desc_digest in inspected_referrers
                ):
                    continue
                if not _is_candidate_referrer(desc):
                    continue
                inspected_referrers.add(desc_digest)
                artifact_type = (
                    clean_optional_str(desc.get("artifactType"))
                    or clean_optional_str(desc.get("mediaType"))
                    or "unknown"
                )
                components.extend(
                    self._extract_components_from_referrer_manifest(
                        ref,
                        subject_digest=subject_digest,
                        referrer_digest=desc_digest,
                        artifact_type=artifact_type,
                    )
                )

        return tuple(components)

    def _is_index_manifest(self, manifest: Mapping[str, Any]) -> bool:
        """Return True if a manifest JSON object represents an OCI Index / Manifest List."""
        media_type = _base_media_type(manifest.get("mediaType"))
        return media_type in _INDEX_MEDIA_TYPES or isinstance(manifest.get("manifests"), list)

    def _select_index_targets(
        self,
        index_manifest: Mapping[str, Any],
    ) -> tuple[list[str], list[str]]:
        """Extract bounded platform child manifests and BuildKit attestation manifests."""
        raw_entries = index_manifest.get("manifests")
        if not isinstance(raw_entries, list):
            return [], []

        platform_digests: list[str] = []
        attestation_manifests: list[tuple[str | None, str]] = []

        for entry in raw_entries:
            if not isinstance(entry, Mapping):
                continue
            digest = clean_optional_str(entry.get("digest"))
            if digest is None or not _is_valid_digest(digest):
                continue

            annotations = entry.get("annotations")
            ref_type = (
                clean_optional_str(annotations.get("vnd.docker.reference.type"))
                if isinstance(annotations, Mapping)
                else None
            )
            if ref_type == "attestation-manifest":
                target_digest = (
                    clean_optional_str(annotations.get("vnd.docker.reference.digest"))
                    if isinstance(annotations, Mapping)
                    else None
                )
                attestation_manifests.append((target_digest, digest))
                continue

            plat = entry.get("platform")
            if isinstance(plat, Mapping):
                plat_os = clean_optional_str(plat.get("os"))
                plat_arch = clean_optional_str(plat.get("architecture"))
                if plat_os == "unknown" and plat_arch == "unknown":
                    continue
                if (
                    self._platform_os is not None
                    and self._platform_arch is not None
                    and (
                        (plat_os or "").lower() != self._platform_os
                        or (plat_arch or "").lower() != self._platform_arch
                    )
                ):
                    continue

            if len(platform_digests) < _MAX_MANIFESTS_PER_IMAGE:
                platform_digests.append(digest)

        selected_platform_set = set(platform_digests)
        matched_attestations: list[str] = []
        for target_digest, att_digest in attestation_manifests:
            if len(matched_attestations) >= _MAX_MANIFESTS_PER_IMAGE:
                break
            if (
                self._platform is None
                or target_digest is None
                or target_digest in selected_platform_set
            ):
                matched_attestations.append(att_digest)

        return platform_digests, matched_attestations

    def _extract_components_from_referrer_manifest(
        self,
        ref: OciImageRef,
        *,
        subject_digest: str,
        referrer_digest: str,
        artifact_type: str,
    ) -> tuple[InventoryComponent, ...]:
        """Download and parse CycloneDX/SPDX SBOM or attestation layers from a referrer."""
        fetched = self._fetch_manifest(ref, referrer_digest)
        if fetched is None:
            return ()
        _, referrer_manifest = fetched

        raw_layers = referrer_manifest.get("layers")
        if not isinstance(raw_layers, list):
            raw_blobs = referrer_manifest.get("blobs")
            raw_layers = raw_blobs if isinstance(raw_blobs, list) else []

        manifest_artifact_type = _base_media_type(referrer_manifest.get("artifactType"))
        effective_artifact_type = manifest_artifact_type or _base_media_type(artifact_type)
        asset_uri = f"oci://{ref.registry}/{ref.repository}@{subject_digest}"
        scope = f"{ref.registry}/{ref.repository}"

        parsed_components: list[InventoryComponent] = []
        for layer in raw_layers[:_MAX_LAYERS_PER_REFERRER]:
            if not isinstance(layer, Mapping):
                continue
            layer_digest = clean_optional_str(layer.get("digest"))
            if layer_digest is None or not _is_valid_digest(layer_digest):
                continue

            layer_media = _base_media_type(layer.get("mediaType"))
            if (
                layer_media not in _SUPPORTED_LAYER_MEDIA_TYPES
                and effective_artifact_type not in _DIRECT_SBOM_MEDIA_TYPES
            ):
                continue

            raw_size = layer.get("size")
            if isinstance(raw_size, int) and raw_size > self._max_sbom_bytes:
                raise BackendQueryError(
                    f"[{self.name}] SBOM layer {layer_digest} declares size {raw_size} > "
                    f"limit {self._max_sbom_bytes} bytes."
                )

            blob = self._fetch_blob(ref, layer_digest)
            if layer_media in _DIRECT_SBOM_MEDIA_TYPES:
                sbom_bytes: bytes | None = blob
            else:
                sbom_bytes = _unwrap_sbom_payload(
                    blob,
                    max_sbom_bytes=self._max_sbom_bytes,
                    context=f"{asset_uri} ({layer_digest})",
                )
            if sbom_bytes is None:
                continue

            try:
                parsed = parse_sbom_bytes(
                    sbom_bytes,
                    asset_id=asset_uri,
                    backend=self.name,
                    location=asset_uri,
                    scope=scope,
                    asset_type="oci_image",
                    extra_metadata={
                        "registry": ref.registry,
                        "repository": ref.repository,
                        "digest": subject_digest,
                        "tag": ref.tag,
                        "sbom_digest": layer_digest,
                        "artifact_type": effective_artifact_type or layer_media,
                    },
                    max_bytes=self._max_sbom_bytes,
                    max_depth=MAX_CYCLONEDX_DEPTH,
                )
            except SbomParseError as exc:
                if layer_media in _DIRECT_SBOM_MEDIA_TYPES:
                    raise BackendQueryError(
                        f"[{self.name}] Failed to parse SBOM layer {layer_digest} "
                        f"on {asset_uri}: {exc}"
                    ) from exc
                continue
            parsed_components.extend(parsed)

        return tuple(parsed_components)
