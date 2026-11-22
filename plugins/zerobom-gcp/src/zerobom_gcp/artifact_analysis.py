"""GCP Artifact Analysis (Container Analysis v1 ``occurrences``) backend plugin."""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from packageurl import PackageURL

from zerobom.backends import (
    BackendConfigError,
    BackendQueryError,
    InMemoryComponentIndex,
    SbomParseError,
    parse_sbom_bytes,
)
from zerobom.backends._http import (
    DEFAULT_API_TIMEOUT_SECONDS,
    DEFAULT_MAX_RESPONSE_BYTES,
    MAX_API_URL_LENGTH,
    REDIRECT_STATUS_CODES,
    parse_bool_opt,
    parse_float_opt,
    parse_int_opt,
    parse_optional_str_opt,
    parse_str_list_opt,
    reject_unknown_config_keys,
    resolve_tls_verify,
    validate_api_base_url,
    validate_bounded_int,
    validate_no_control_chars,
    validate_timeout_seconds,
)
from zerobom.backends.sbom_parser import (
    MAX_SBOM_FILE_BYTES,
    build_safe_metadata,
    clean_optional_str,
    make_inventory_component,
)
from zerobom.models import AssetRef, InventoryComponent, PackageQuery
from zerobom_gcp._auth import GcpTokenProvider
from zerobom_gcp._common import (
    build_gcp_http_client,
    decode_json_dict,
    maybe_decompress_sbom_bytes,
    parse_gs_uri,
    request_with_retry,
    validate_gcs_bucket_allowlist,
)

DEFAULT_ARTIFACT_ANALYSIS_URL = "https://containeranalysis.googleapis.com"
DEFAULT_GCS_API_URL = "https://storage.googleapis.com"
_GCP_PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9.:-]{1,62}$")
_GCP_LOCATION_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
_CEL_SAFE_PKG_RE = re.compile(r"^[A-Za-z0-9._/@:+-]{1,256}$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_OS_CPE_22_RE = re.compile(
    r"^cpe:/o:([a-z0-9_-]+):([a-z0-9_.-]+):([0-9]+(?:\.[0-9]+)*)(?::|$)",
    re.IGNORECASE,
)
_OS_CPE_23_RE = re.compile(
    r"^cpe:2\.3:o:([a-z0-9_-]+):([a-z0-9_.-]+):([0-9]+(?:\.[0-9]+)*)(?::|$)",
    re.IGNORECASE,
)

_PACKAGE_TYPE_TO_ECOSYSTEM: dict[str, str] = {
    "PYPI": "pypi",
    "PYTHON": "pypi",
    "NPM": "npm",
    "MAVEN": "maven",
    "GO": "golang",
    "GOLANG": "golang",
    "GO_STDLIB": "golang",
    "RUBY": "gem",
    "RUBYGEMS": "gem",
    "GEM": "gem",
    "CARGO": "cargo",
    "RUST": "cargo",
    "COMPOSER": "composer",
    "PHP": "composer",
    "NUGET": "nuget",
    "DEB": "deb",
    "RPM": "rpm",
    "ALPINE": "apk",
    "APK": "apk",
}
_OS_PACKAGE_TYPES: frozenset[str] = frozenset({"", "OS", "DEB", "RPM", "ALPINE", "APK"})
_VALID_MODES: frozenset[str] = frozenset({"package", "sbom_reference", "both"})

_ALLOWED_CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "project_id",
        "location",
        "mode",
        "access_token",
        "use_adc",
        "user_project",
        "resource_uri_prefix",
        "filter_by_package",
        "api_base_url",
        "gcs_api_base_url",
        "allowed_sbom_buckets",
        "verify_sbom_digest",
        "max_sbom_objects",
        "max_sbom_bytes",
        "max_concurrency",
        "max_retries",
        "page_size",
        "max_pages",
        "timeout_seconds",
        "max_response_bytes",
        "ca_bundle",
        "verify_tls",
        "allow_insecure_http",
        "strict",
    }
)


def _format_version_obj(version_obj: Any) -> str | None:
    """Extract a normalized version string from a Container Analysis ``Version`` object."""
    if not isinstance(version_obj, Mapping):
        return clean_optional_str(version_obj)
    full_name = clean_optional_str(version_obj.get("fullName"))
    if full_name is not None:
        return full_name
    name = clean_optional_str(version_obj.get("name"))
    if name is None:
        return None
    revision = clean_optional_str(version_obj.get("revision"))
    epoch = version_obj.get("epoch")
    base = f"{name}-{revision}" if revision else name
    if isinstance(epoch, int) and not isinstance(epoch, bool) and epoch > 0:
        return f"{epoch}:{base}"
    return base


def _parse_os_cpe(cpe_uri: str | None) -> tuple[str, str, str] | None:
    """Parse CPE 2.2 or 2.3 OS strings into ``(purl_type, distro_namespace, distro_release)``."""
    if not cpe_uri:
        return None
    text = cpe_uri.strip()
    match = _OS_CPE_22_RE.match(text) or _OS_CPE_23_RE.match(text)
    if not match:
        return None

    vendor = match.group(1).lower()
    product = match.group(2).lower()
    ver = match.group(3)
    major = ver.split(".", 1)[0]
    major_minor = ".".join(ver.split(".")[:2])

    if vendor == "debian" or "debian" in product:
        return ("deb", "debian", f"debian-{major}")
    if vendor == "canonical" or "ubuntu" in product:
        return ("deb", "ubuntu", f"ubuntu-{major_minor}")
    if vendor == "alpinelinux" or "alpine" in product:
        return ("apk", "alpine", f"alpine-{major_minor}")
    if vendor == "wolfi" or "wolfi" in product:
        return ("apk", "wolfi", f"wolfi-{major_minor}")
    if vendor == "chainguard" or "chainguard" in product:
        return ("apk", "chainguard", f"chainguard-{major_minor}")
    if "redhat" in vendor or "rhel" in product or "enterprise_linux" in product:
        return ("rpm", "redhat", f"rhel-{major}")
    if "rocky" in vendor or "rocky" in product:
        return ("rpm", "rocky", f"rocky-{major}")
    if "almalinux" in vendor or "almalinux" in product:
        return ("rpm", "almalinux", f"almalinux-{major}")
    if "centos" in vendor or "centos" in product:
        return ("rpm", "centos", f"centos-{major}")
    if "amazon" in vendor or "amazon_linux" in product or "amzn" in product:
        return ("rpm", "amazonlinux", f"amazonlinux-{ver}")
    if "oracle" in vendor or "oracle" in product:
        return ("rpm", "oracle", f"oraclelinux-{major}")
    if "suse" in vendor or "sles" in product or "opensuse" in product:
        return ("rpm", "suse", f"sles-{major}")
    return None


def _lookup_names_for_query(query: PackageQuery) -> tuple[str, ...]:
    """Generate Container Analysis ``dependencyPackageName`` lookup candidates."""
    candidates: list[str] = [query.name]
    if query.namespace:
        if query.ecosystem == "maven":
            candidates.append(f"{query.namespace}:{query.name}")
        elif query.ecosystem in {"npm", "golang", "composer"}:
            candidates.append(f"{query.namespace}/{query.name}")
    seen: set[str] = set()
    ordered: list[str] = []
    for cand in candidates:
        if cand not in seen:
            seen.add(cand)
            ordered.append(cand)
    return tuple(ordered)


def _build_concrete_purl(
    *,
    pkg_name: str,
    ver_str: str,
    ecosystem: str | None,
    namespace_hint: str | None,
) -> str | None:
    """Build a versioned PURL when Artifact Analysis reports a non-OS ecosystem type."""
    if ecosystem is None or ecosystem not in _PACKAGE_TYPE_TO_ECOSYSTEM.values():
        return None
    purl_ns = namespace_hint
    purl_name = pkg_name
    if ecosystem == "maven" and ":" in pkg_name and purl_ns is None:
        purl_ns, _, purl_name = pkg_name.partition(":")
    elif ecosystem in {"npm", "golang", "composer"} and "/" in pkg_name and purl_ns is None:
        purl_ns, _, purl_name = pkg_name.rsplit("/", 1)
    try:
        return str(PackageURL(type=ecosystem, namespace=purl_ns, name=purl_name, version=ver_str))
    except ValueError:
        return None


def _extract_sha256_digest(predicate: Mapping[str, Any]) -> str | None:
    """Extract normalized SHA-256 hex digest from an ``SbomReferenceIntotoPredicate``."""
    for field in ("digest", "digests"):
        digest_map = predicate.get(field)
        if isinstance(digest_map, Mapping):
            raw_sha = clean_optional_str(digest_map.get("sha256"))
            if raw_sha is not None:
                return raw_sha.lower()
    return None


class GcpArtifactAnalysisBackend:
    """Query-driven GCP Artifact Analysis (Container Analysis v1 ``occurrences``) backend."""

    def __init__(
        self,
        *,
        project_id: str,
        location: str | None = None,
        mode: str = "package",
        access_token: str | None = None,
        use_adc: bool | None = None,
        user_project: str | None = None,
        resource_uri_prefix: str | None = None,
        filter_by_package: bool = True,
        api_base_url: str = DEFAULT_ARTIFACT_ANALYSIS_URL,
        gcs_api_base_url: str = DEFAULT_GCS_API_URL,
        allowed_sbom_buckets: Sequence[str] = (),
        verify_sbom_digest: bool = True,
        max_sbom_objects: int = 500,
        max_sbom_bytes: int = MAX_SBOM_FILE_BYTES,
        max_concurrency: int = 8,
        max_retries: int = 3,
        page_size: int = 100,
        max_pages: int = 50,
        timeout_seconds: float = DEFAULT_API_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        ca_bundle: str | Path | None = None,
        verify_tls: bool = True,
        allow_insecure_http: bool = False,
        strict: bool = False,
        http_client: httpx.Client | None = None,
        token_provider: GcpTokenProvider | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        """Initialize a GCP Artifact Analysis v1 inventory backend.

        Raises:
            BackendConfigError: If ``project_id``, location, mode, URLs, credentials, TLS,
                or bounds are invalid.
        """
        if use_adc is not None and not isinstance(use_adc, bool):
            raise BackendConfigError("Configuration option 'use_adc' must be a bool.")
        if not isinstance(filter_by_package, bool):
            raise BackendConfigError("Configuration option 'filter_by_package' must be a bool.")
        if not isinstance(verify_sbom_digest, bool):
            raise BackendConfigError("Configuration option 'verify_sbom_digest' must be a bool.")
        if not isinstance(verify_tls, bool):
            raise BackendConfigError("Configuration option 'verify_tls' must be a bool.")
        if not isinstance(allow_insecure_http, bool):
            raise BackendConfigError("Configuration option 'allow_insecure_http' must be a bool.")
        if not isinstance(strict, bool):
            raise BackendConfigError("Configuration option 'strict' must be a bool.")

        cleaned_project = validate_no_control_chars(
            project_id, field_name="project_id", max_length=64
        )
        if ".." in cleaned_project or not _GCP_PROJECT_RE.fullmatch(cleaned_project):
            raise BackendConfigError(f"Invalid GCP project_id: {project_id!r}.")
        self._project_id = cleaned_project

        self._location: str | None = None
        if location is not None:
            cleaned_loc = validate_no_control_chars(location, field_name="location", max_length=32)
            if not _GCP_LOCATION_RE.fullmatch(cleaned_loc):
                raise BackendConfigError(f"Invalid GCP location: {location!r}.")
            self._location = cleaned_loc

        cleaned_mode = validate_no_control_chars(mode, field_name="mode", max_length=32).lower()
        if cleaned_mode not in _VALID_MODES:
            raise BackendConfigError(
                f"Invalid mode {mode!r}; expected one of {sorted(_VALID_MODES)}."
            )
        self._mode = cleaned_mode

        self._user_project: str | None = None
        if user_project is not None:
            cleaned_up = validate_no_control_chars(
                user_project, field_name="user_project", max_length=64
            )
            if ".." in cleaned_up or not _GCP_PROJECT_RE.fullmatch(cleaned_up):
                raise BackendConfigError(f"Invalid GCP user_project: {user_project!r}.")
            self._user_project = cleaned_up

        self._resource_uri_prefix: str | None = None
        if resource_uri_prefix is not None:
            cleaned_prefix = validate_no_control_chars(
                resource_uri_prefix, field_name="resource_uri_prefix", max_length=512
            )
            if '"' in cleaned_prefix or "\\" in cleaned_prefix:
                raise BackendConfigError(
                    "Configuration option 'resource_uri_prefix' must not contain "
                    "quotes or backslashes."
                )
            self._resource_uri_prefix = cleaned_prefix

        self._api_base_url = validate_api_base_url(
            api_base_url,
            allow_insecure_http=allow_insecure_http,
            field_name="api_base_url",
        )
        self._gcs_api_base_url = validate_api_base_url(
            gcs_api_base_url,
            allow_insecure_http=allow_insecure_http,
            field_name="gcs_api_base_url",
        )
        self._allowed_sbom_buckets = frozenset(validate_gcs_bucket_allowlist(allowed_sbom_buckets))
        self._token_provider = token_provider or GcpTokenProvider(
            access_token=access_token, use_adc=use_adc
        )
        if self._user_project is None and self._token_provider.quota_project_id is not None:
            self._user_project = self._token_provider.quota_project_id

        self._filter_by_package = filter_by_package
        self._verify_sbom_digest = verify_sbom_digest
        self._max_sbom_objects = validate_bounded_int(
            max_sbom_objects, field_name="max_sbom_objects", min_value=1, max_value=10000
        )
        self._max_sbom_bytes = validate_bounded_int(
            max_sbom_bytes,
            field_name="max_sbom_bytes",
            min_value=1024,
            max_value=200 * 1024 * 1024,
        )
        self._max_concurrency = validate_bounded_int(
            max_concurrency, field_name="max_concurrency", min_value=1, max_value=32
        )
        self._max_retries = validate_bounded_int(
            max_retries, field_name="max_retries", min_value=0, max_value=10
        )
        self._page_size = validate_bounded_int(
            page_size, field_name="page_size", min_value=1, max_value=1000
        )
        self._max_pages = validate_bounded_int(
            max_pages, field_name="max_pages", min_value=1, max_value=500
        )
        self._timeout_seconds = validate_timeout_seconds(timeout_seconds)
        self._max_response_bytes = validate_bounded_int(
            max_response_bytes,
            field_name="max_response_bytes",
            min_value=1024,
            max_value=100 * 1024 * 1024,
        )
        self._strict = strict
        self._sleep_fn = sleep_fn
        self._sbom_ref_index: InMemoryComponentIndex | None = None

        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            verify_arg = resolve_tls_verify(verify_tls=verify_tls, ca_bundle=ca_bundle)
            self._client = build_gcp_http_client(
                timeout_seconds=self._timeout_seconds,
                verify=verify_arg,
                max_concurrency=self._max_concurrency,
            )
            self._owns_client = True

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> GcpArtifactAnalysisBackend:
        """Instantiate :class:`GcpArtifactAnalysisBackend` from CLI or file config."""
        reject_unknown_config_keys(
            config, _ALLOWED_CONFIG_KEYS, backend_name="gcp_artifact_analysis"
        )
        project_id = parse_optional_str_opt(
            config, "project_id", env_var="ZEROBOM_GCP_PROJECT_ID", max_length=64
        )
        if project_id is None:
            raise BackendConfigError(
                "GcpArtifactAnalysisBackend requires 'project_id' (or ZEROBOM_GCP_PROJECT_ID)."
            )

        raw_use_adc = (
            parse_bool_opt(config, "use_adc", default=False)
            if "use_adc" in config and config["use_adc"] is not None
            else None
        )

        return cls(
            project_id=project_id,
            location=parse_optional_str_opt(config, "location", max_length=32),
            mode=parse_optional_str_opt(config, "mode", max_length=32) or "package",
            access_token=parse_optional_str_opt(config, "access_token", max_length=8192),
            use_adc=raw_use_adc,
            user_project=parse_optional_str_opt(config, "user_project", max_length=64),
            resource_uri_prefix=parse_optional_str_opt(
                config, "resource_uri_prefix", max_length=512
            ),
            filter_by_package=parse_bool_opt(config, "filter_by_package", default=True),
            api_base_url=parse_optional_str_opt(
                config, "api_base_url", max_length=MAX_API_URL_LENGTH
            )
            or DEFAULT_ARTIFACT_ANALYSIS_URL,
            gcs_api_base_url=parse_optional_str_opt(
                config, "gcs_api_base_url", max_length=MAX_API_URL_LENGTH
            )
            or DEFAULT_GCS_API_URL,
            allowed_sbom_buckets=parse_str_list_opt(
                config, "allowed_sbom_buckets", max_items=100, max_item_length=222
            ),
            verify_sbom_digest=parse_bool_opt(config, "verify_sbom_digest", default=True),
            max_sbom_objects=parse_int_opt(
                config, "max_sbom_objects", default=500, min_value=1, max_value=10000
            ),
            max_sbom_bytes=parse_int_opt(
                config,
                "max_sbom_bytes",
                default=MAX_SBOM_FILE_BYTES,
                min_value=1024,
                max_value=200 * 1024 * 1024,
            ),
            max_concurrency=parse_int_opt(
                config, "max_concurrency", default=8, min_value=1, max_value=32
            ),
            max_retries=parse_int_opt(config, "max_retries", default=3, min_value=0, max_value=10),
            page_size=parse_int_opt(config, "page_size", default=100, min_value=1, max_value=1000),
            max_pages=parse_int_opt(config, "max_pages", default=50, min_value=1, max_value=500),
            timeout_seconds=parse_float_opt(
                config,
                "timeout_seconds",
                default=DEFAULT_API_TIMEOUT_SECONDS,
                min_value=0.5,
                max_value=120.0,
            ),
            max_response_bytes=parse_int_opt(
                config,
                "max_response_bytes",
                default=DEFAULT_MAX_RESPONSE_BYTES,
                min_value=1024,
                max_value=100 * 1024 * 1024,
            ),
            ca_bundle=parse_optional_str_opt(config, "ca_bundle", max_length=2048),
            verify_tls=parse_bool_opt(config, "verify_tls", default=True),
            allow_insecure_http=parse_bool_opt(config, "allow_insecure_http", default=False),
            strict=parse_bool_opt(config, "strict", default=False),
        )

    @property
    def name(self) -> str:
        """Registered backend plugin identifier (``"gcp_artifact_analysis"``)."""
        return "gcp_artifact_analysis"

    def close(self) -> None:
        """Close the internally managed HTTP client session."""
        if self._owns_client:
            self._client.close()

    def __repr__(self) -> str:
        """Return a redacted summary without leaking GCP bearer credentials."""
        return (
            f"GcpArtifactAnalysisBackend(project_id={self._project_id!r}, "
            f"location={self._location!r}, mode={self._mode!r}, "
            f"api_base_url={self._api_base_url!r})"
        )

    def _occurrences_endpoint(self) -> str:
        """Build the global or regional Container Analysis occurrences endpoint URL."""
        proj = quote(self._project_id, safe="")
        if self._location is not None:
            loc = quote(self._location, safe="")
            return f"{self._api_base_url}/v1/projects/{proj}/locations/{loc}/occurrences"
        return f"{self._api_base_url}/v1/projects/{proj}/occurrences"

    def _request_headers(self) -> dict[str, str]:
        """Build base HTTP headers (excluding Authorization, injected per attempt)."""
        headers = {"Accept": "application/json"}
        if self._user_project is not None:
            headers["X-Goog-User-Project"] = self._user_project
        return headers

    def _build_cel_filter(self, pkg_name: str | None, *, kind: str = "PACKAGE") -> str:
        """Construct an AIP-160 filter expression using allowlist-validated identifiers."""
        clauses = [f'kind="{kind}"']
        if self._resource_uri_prefix is not None:
            clauses.append(f'has_prefix(resourceUrl, "{self._resource_uri_prefix}")')
        if pkg_name is not None and kind == "PACKAGE":
            if not _CEL_SAFE_PKG_RE.fullmatch(pkg_name):
                raise BackendQueryError(
                    f"[{self.name}] Unsafe package identifier {pkg_name!r} rejected by "
                    "filter guard."
                )
            clauses.append(f'dependencyPackageName="{pkg_name}"')
        return " AND ".join(clauses)

    def _find_package_components(
        self, queries: Sequence[PackageQuery]
    ) -> tuple[InventoryComponent, ...]:
        """Query Container Analysis ``kind="PACKAGE"`` occurrences matching ``queries``."""
        index = InMemoryComponentIndex()
        if not self._filter_by_package:
            for occ in self._fetch_occurrences(pkg_name=None, kind="PACKAGE"):
                index.add_components(self._occurrence_to_components(occ, fallback_eco=None))
            return index.find_components(queries)

        lookup_to_queries: dict[str, list[PackageQuery]] = {}
        for query in queries:
            for lookup_name in _lookup_names_for_query(query):
                lookup_to_queries.setdefault(lookup_name, []).append(query)

        for lookup_name, matching_queries in lookup_to_queries.items():
            distinct_ecos = {q.ecosystem for q in matching_queries}
            fallback_eco = matching_queries[0].ecosystem if len(distinct_ecos) == 1 else None
            ns_hint = (
                matching_queries[0].namespace
                if len(matching_queries) == 1 and matching_queries[0].name == lookup_name
                else None
            )
            for occ in self._fetch_occurrences(pkg_name=lookup_name, kind="PACKAGE"):
                index.add_components(
                    self._occurrence_to_components(
                        occ,
                        fallback_eco=fallback_eco,
                        fallback_ns=ns_hint,
                    )
                )

        return index.find_components(queries)

    def _load_sbom_references(self) -> InMemoryComponentIndex:
        """Fetch ``kind="SBOM_REFERENCE"`` occurrences and verify/index GCS SBOMs."""
        occurrences = self._fetch_occurrences(pkg_name=None, kind="SBOM_REFERENCE")
        refs: list[tuple[str, str, str, str, str, str | None]] = []

        for occ in occurrences:
            if clean_optional_str(occ.get("kind")) not in (None, "SBOM_REFERENCE"):
                continue
            sbom_ref = occ.get("sbomReference")
            if not isinstance(sbom_ref, Mapping):
                continue
            payload = sbom_ref.get("payload")
            if not isinstance(payload, Mapping):
                continue
            predicate = payload.get("predicate")
            if not isinstance(predicate, Mapping):
                continue
            raw_loc = clean_optional_str(predicate.get("location"))
            if raw_loc is None:
                continue

            bucket, obj_path = parse_gs_uri(raw_loc, backend_name=self.name)
            if self._allowed_sbom_buckets and bucket not in self._allowed_sbom_buckets:
                raise BackendQueryError(
                    f"[{self.name}] GCS bucket {bucket!r} in SBOM_REFERENCE {raw_loc!r} is "
                    "outside configured allowed_sbom_buckets."
                )

            expected_sha = _extract_sha256_digest(predicate)
            if expected_sha is not None and not _SHA256_HEX_RE.fullmatch(expected_sha):
                raise BackendQueryError(
                    f"[{self.name}] Malformed sha256 digest {expected_sha!r} in "
                    f"SBOM_REFERENCE {raw_loc!r}."
                )

            occ_name = clean_optional_str(occ.get("name")) or "sbom_reference"
            res_obj = occ.get("resource")
            resource_uri = (
                clean_optional_str(occ.get("resourceUri"))
                or clean_optional_str(occ.get("resourceUrl"))
                or (
                    clean_optional_str(res_obj.get("uri")) if isinstance(res_obj, Mapping) else None
                )
            )
            refs.append(
                (occ_name, resource_uri or occ_name, raw_loc, bucket, obj_path, expected_sha)
            )
            if len(refs) > self._max_sbom_objects:
                raise BackendQueryError(
                    f"[{self.name}] SBOM_REFERENCE count exceeded "
                    f"max_sbom_objects={self._max_sbom_objects}."
                )

        def _fetch_and_parse(
            item: tuple[str, str, str, str, str, str | None],
        ) -> tuple[InventoryComponent, ...]:
            occ_name, resource_uri, gs_uri, bucket, obj_path, expected_sha = item
            obj_url = (
                f"{self._gcs_api_base_url}/storage/v1/b/{quote(bucket, safe='')}/o/"
                f"{quote(obj_path, safe='')}"
            )
            params: dict[str, str] = {"alt": "media"}
            if self._user_project is not None:
                params["userProject"] = self._user_project

            status, resp_headers, raw_bytes = request_with_retry(
                self._client,
                "GET",
                obj_url,
                token_provider=self._token_provider,
                max_bytes=self._max_sbom_bytes,
                backend_name=self.name,
                params=params,
                headers=self._request_headers(),
                max_retries=self._max_retries,
                sleep_fn=self._sleep_fn,
            )
            self._check_status(status, obj_url)

            if self._verify_sbom_digest and expected_sha is not None:
                actual_sha = hashlib.sha256(raw_bytes).hexdigest()
                if not hmac.compare_digest(actual_sha, expected_sha):
                    raise BackendQueryError(
                        f"[{self.name}] SHA-256 digest mismatch for SBOM_REFERENCE {gs_uri} "
                        f"(expected {expected_sha}, got {actual_sha})."
                    )

            try:
                plain_bytes = maybe_decompress_sbom_bytes(
                    raw_bytes,
                    object_label=gs_uri,
                    content_encoding=clean_optional_str(resp_headers.get("content-encoding")),
                    max_bytes=self._max_sbom_bytes,
                    backend_name=self.name,
                )
                return parse_sbom_bytes(
                    plain_bytes,
                    asset_id=resource_uri,
                    backend=self.name,
                    location=resource_uri,
                    scope=self._project_id,
                    asset_type="gcp_artifact",
                    extra_metadata={
                        "project_id": self._project_id,
                        "occurrence_name": occ_name,
                        "sbom_gcs_uri": gs_uri,
                    },
                    max_bytes=self._max_sbom_bytes,
                )
            except SbomParseError as exc:
                if self._strict:
                    raise BackendQueryError(
                        f"[{self.name}] Failed to parse SBOM_REFERENCE {gs_uri}: {exc}"
                    ) from exc
                return ()

        index = InMemoryComponentIndex()
        if self._max_concurrency > 1 and len(refs) > 1:
            ordered: list[tuple[InventoryComponent, ...] | None] = [None] * len(refs)
            with ThreadPoolExecutor(max_workers=min(self._max_concurrency, len(refs))) as pool:
                future_to_idx: dict[Future[tuple[InventoryComponent, ...]], int] = {
                    pool.submit(_fetch_and_parse, ref): idx for idx, ref in enumerate(refs)
                }
                try:
                    for fut in as_completed(future_to_idx):
                        ordered[future_to_idx[fut]] = fut.result()
                except Exception:
                    for pending in future_to_idx:
                        pending.cancel()
                    raise
            for comps in ordered:
                if comps:
                    index.add_components(comps)
        else:
            for ref in refs:
                comps = _fetch_and_parse(ref)
                if comps:
                    index.add_components(comps)

        self._sbom_ref_index = index
        return index

    def find_components(self, queries: Sequence[PackageQuery]) -> tuple[InventoryComponent, ...]:
        """Query Container Analysis ``PACKAGE`` and/or ``SBOM_REFERENCE`` records."""
        if not queries:
            return ()

        if self._mode == "package":
            return self._find_package_components(queries)

        if self._sbom_ref_index is None:
            self._load_sbom_references()

        if self._mode == "sbom_reference":
            return self._sbom_ref_index.find_components(queries) if self._sbom_ref_index else ()

        merged = InMemoryComponentIndex()
        merged.add_components(self._find_package_components(queries))
        if self._sbom_ref_index is not None:
            merged.add_components(self._sbom_ref_index.find_components(queries))
        return merged.find_components(queries)

    def _fetch_occurrences(self, *, pkg_name: str | None, kind: str) -> list[dict[str, Any]]:
        """Paginate ``occurrences`` endpoint up to ``max_pages`` with bounded retries."""
        endpoint = self._occurrences_endpoint()
        headers = self._request_headers()
        cel_filter = self._build_cel_filter(pkg_name, kind=kind)

        results: list[dict[str, Any]] = []
        page_token: str | None = None

        for _ in range(self._max_pages):
            params: dict[str, str] = {
                "filter": cel_filter,
                "pageSize": str(self._page_size),
            }
            if page_token is not None:
                params["pageToken"] = page_token

            status, _, body = request_with_retry(
                self._client,
                "GET",
                endpoint,
                token_provider=self._token_provider,
                max_bytes=self._max_response_bytes,
                backend_name=self.name,
                params=params,
                headers=headers,
                max_retries=self._max_retries,
                sleep_fn=self._sleep_fn,
            )
            self._check_status(status, endpoint)
            doc = decode_json_dict(body, endpoint, self.name)

            raw_occ = doc.get("occurrences")
            if isinstance(raw_occ, list):
                for entry in raw_occ:
                    if isinstance(entry, Mapping):
                        results.append(dict(entry))

            page_token = clean_optional_str(doc.get("nextPageToken"))
            if page_token is None:
                return results

        raise BackendQueryError(
            f"[{self.name}] Container Analysis pagination exceeded max_pages={self._max_pages}."
        )

    def _check_status(self, status: int, url: str) -> None:
        """Fail closed on redirects, IAM denials, rate limits, and non-200 responses."""
        if status in REDIRECT_STATUS_CODES:
            raise BackendQueryError(
                f"[{self.name}] Unexpected HTTP redirect ({status}) from {url}; redirects disabled."
            )
        if status in (401, 403):
            raise BackendQueryError(
                f"[{self.name}] GCP IAM/OAuth authentication denied ({status}) at {url}."
            )
        if status == 404:
            raise BackendQueryError(
                f"[{self.name}] GCP project or occurrences endpoint not found (404) at {url}."
            )
        if status == 429:
            raise BackendQueryError(f"[{self.name}] GCP API rate limited (429) at {url}.")
        if status != 200:
            raise BackendQueryError(
                f"[{self.name}] GCP Artifact Analysis returned status {status} at {url}."
            )

    def _occurrence_to_components(
        self,
        occ: Mapping[str, Any],
        *,
        fallback_eco: str | None,
        fallback_ns: str | None = None,
    ) -> tuple[InventoryComponent, ...]:
        """Convert one Grafeas ``PACKAGE`` occurrence into normalized components."""
        if clean_optional_str(occ.get("kind")) not in (None, "PACKAGE"):
            return ()
        pkg_obj = occ.get("package") or occ.get("installation")
        if not isinstance(pkg_obj, Mapping):
            return ()

        pkg_name = clean_optional_str(pkg_obj.get("name"))
        if pkg_name is None:
            return ()

        occ_name = clean_optional_str(occ.get("name")) or "occurrence"
        res_obj = occ.get("resource")
        resource_uri = (
            clean_optional_str(occ.get("resourceUri"))
            or clean_optional_str(occ.get("resourceUrl"))
            or (clean_optional_str(res_obj.get("uri")) if isinstance(res_obj, Mapping) else None)
        )
        pkg_type_raw = (clean_optional_str(pkg_obj.get("packageType")) or "").upper()
        mapped_eco = _PACKAGE_TYPE_TO_ECOSYSTEM.get(pkg_type_raw)
        eco_hint = mapped_eco or fallback_eco
        top_cpe = clean_optional_str(pkg_obj.get("cpeUri"))

        asset = AssetRef(
            asset_id=resource_uri or occ_name,
            asset_type="gcp_artifact",
            backend=self.name,
            scope=self._project_id,
            location=resource_uri,
            metadata=build_safe_metadata(
                {
                    "project_id": self._project_id,
                    "occurrence_name": occ_name,
                    "package_type": pkg_type_raw or None,
                    "architecture": clean_optional_str(pkg_obj.get("architecture")),
                }
            ),
        )

        top_ver = _format_version_obj(pkg_obj.get("version"))
        candidates: list[tuple[str, str | None]] = []
        raw_locations = pkg_obj.get("location")
        if isinstance(raw_locations, list):
            for loc in raw_locations:
                if not isinstance(loc, Mapping):
                    continue
                loc_ver = _format_version_obj(loc.get("version")) or top_ver
                cpe_uri = clean_optional_str(loc.get("cpeUri")) or top_cpe
                if loc_ver is not None:
                    candidates.append((loc_ver, cpe_uri))

        if not candidates and top_ver is not None:
            candidates.append((top_ver, top_cpe))

        components: list[InventoryComponent] = []
        for ver_str, cpe_uri in candidates:
            raw_purl: str | None = None
            comp_eco = eco_hint
            comp_ns: str | None = fallback_ns

            os_info = _parse_os_cpe(cpe_uri)
            if os_info is not None and pkg_type_raw in _OS_PACKAGE_TYPES:
                purl_type, distro_ns, distro_rel = os_info
                comp_eco = purl_type
                comp_ns = distro_ns
                raw_purl = (
                    f"pkg:{purl_type}/{quote(distro_ns, safe='')}/"
                    f"{quote(pkg_name, safe='')}@{quote(ver_str, safe='')}?distro={distro_rel}"
                )
            elif mapped_eco is not None:
                raw_purl = _build_concrete_purl(
                    pkg_name=pkg_name,
                    ver_str=ver_str,
                    ecosystem=mapped_eco,
                    namespace_hint=comp_ns,
                )

            comp = make_inventory_component(
                raw_name=pkg_name,
                raw_version=ver_str,
                raw_purl=raw_purl,
                ecosystem_hint=comp_eco,
                namespace_hint=comp_ns,
                asset=asset,
                bom_ref=occ_name,
            )
            if comp is not None:
                components.append(comp)

        return tuple(components)
