"""GCP Artifact Analysis (Container Analysis v1) software inventory backend plugin."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from packageurl import PackageURL

from zerobom.backends import (
    BackendConfigError,
    BackendQueryError,
    InMemoryComponentIndex,
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
    read_bounded_response,
    reject_unknown_config_keys,
    resolve_tls_verify,
    validate_api_base_url,
    validate_bounded_int,
    validate_no_control_chars,
    validate_timeout_seconds,
)
from zerobom.backends.sbom_parser import (
    build_safe_metadata,
    clean_optional_str,
    make_inventory_component,
)
from zerobom.models import AssetRef, InventoryComponent, PackageQuery
from zerobom_gcp._auth import resolve_gcp_bearer_token

DEFAULT_ARTIFACT_ANALYSIS_URL = "https://containeranalysis.googleapis.com"
_GCP_PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9.:-]{1,62}$")
_CEL_SAFE_PKG_RE = re.compile(r"^[A-Za-z0-9._/@:+-]{1,256}$")
_OS_CPE_RE = re.compile(
    r"^cpe:/o:([a-z0-9_-]+):([a-z0-9_-]+):([0-9]+(?:\.[0-9]+)?)$", re.IGNORECASE
)

_PACKAGE_TYPE_TO_ECOSYSTEM: dict[str, str] = {
    "PYPI": "pypi",
    "NPM": "npm",
    "MAVEN": "maven",
    "GO": "golang",
    "GOLANG": "golang",
    "RUBY": "gem",
    "GEM": "gem",
    "CARGO": "cargo",
    "RUST": "cargo",
    "COMPOSER": "composer",
    "PHP": "composer",
    "NUGET": "nuget",
}

_ALLOWED_CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "project_id",
        "access_token",
        "use_adc",
        "resource_uri_prefix",
        "filter_by_package",
        "api_base_url",
        "page_size",
        "max_pages",
        "timeout_seconds",
        "max_response_bytes",
        "ca_bundle",
        "verify_tls",
        "allow_insecure_http",
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
    if isinstance(epoch, int) and epoch > 0:
        return f"{epoch}:{base}"
    return base


def _parse_os_cpe(cpe_uri: str | None) -> tuple[str, str, str] | None:
    """Parse common OS CPE strings into ``(purl_type, distro_namespace, distro_release)``."""
    if not cpe_uri:
        return None
    match = _OS_CPE_RE.match(cpe_uri.strip())
    if not match:
        return None
    vendor = match.group(1).lower()
    product = match.group(2).lower()
    ver = match.group(3)
    if vendor == "debian" or "debian" in product:
        return ("deb", "debian", f"debian-{ver}")
    if vendor == "canonical" or "ubuntu" in product:
        return ("deb", "ubuntu", f"ubuntu-{ver}")
    if vendor == "alpinelinux" or "alpine" in product:
        major_minor = ".".join(ver.split(".")[:2])
        return ("apk", "alpine", f"alpine-{major_minor}")
    if "redhat" in vendor or "rhel" in product or "enterprise_linux" in product:
        major = ver.split(".", 1)[0]
        return ("rpm", "redhat", f"rhel-{major}")
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


class GcpArtifactAnalysisBackend:
    """Query-driven GCP Artifact Analysis (Container Analysis v1 ``occurrences``) backend."""

    def __init__(
        self,
        *,
        project_id: str,
        access_token: str | None = None,
        use_adc: bool = False,
        resource_uri_prefix: str | None = None,
        filter_by_package: bool = True,
        api_base_url: str = DEFAULT_ARTIFACT_ANALYSIS_URL,
        page_size: int = 100,
        max_pages: int = 50,
        timeout_seconds: float = DEFAULT_API_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        ca_bundle: str | Path | None = None,
        verify_tls: bool = True,
        allow_insecure_http: bool = False,
        http_client: httpx.Client | None = None,
    ) -> None:
        """Initialize a GCP Artifact Analysis v1 inventory backend.

        Raises:
            BackendConfigError: If ``project_id``, URL, credential, TLS, or bounds are invalid.
        """
        if not isinstance(use_adc, bool):
            raise BackendConfigError("Configuration option 'use_adc' must be a bool.")
        if not isinstance(filter_by_package, bool):
            raise BackendConfigError("Configuration option 'filter_by_package' must be a bool.")
        if not isinstance(verify_tls, bool):
            raise BackendConfigError("Configuration option 'verify_tls' must be a bool.")
        if not isinstance(allow_insecure_http, bool):
            raise BackendConfigError("Configuration option 'allow_insecure_http' must be a bool.")

        cleaned_project = validate_no_control_chars(
            project_id, field_name="project_id", max_length=64
        )
        if ".." in cleaned_project or not _GCP_PROJECT_RE.fullmatch(cleaned_project):
            raise BackendConfigError(f"Invalid GCP project_id: {project_id!r}.")
        self._project_id = cleaned_project

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
        self._bearer_token = resolve_gcp_bearer_token(access_token, use_adc=use_adc)
        self._filter_by_package = filter_by_package
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

        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            verify_arg = resolve_tls_verify(verify_tls=verify_tls, ca_bundle=ca_bundle)
            self._client = httpx.Client(
                timeout=self._timeout_seconds,
                verify=verify_arg,
                follow_redirects=False,
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

        return cls(
            project_id=project_id,
            access_token=parse_optional_str_opt(config, "access_token", max_length=8192),
            use_adc=parse_bool_opt(config, "use_adc", default=False),
            resource_uri_prefix=parse_optional_str_opt(
                config, "resource_uri_prefix", max_length=512
            ),
            filter_by_package=parse_bool_opt(config, "filter_by_package", default=True),
            api_base_url=parse_optional_str_opt(
                config, "api_base_url", max_length=MAX_API_URL_LENGTH
            )
            or DEFAULT_ARTIFACT_ANALYSIS_URL,
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
            f"api_base_url={self._api_base_url!r})"
        )

    def _build_cel_filter(self, pkg_name: str | None) -> str:
        """Construct an AIP-160 filter expression using allowlist-validated identifiers."""
        clauses = ['kind="PACKAGE"']
        if self._resource_uri_prefix is not None:
            clauses.append(f'has_prefix(resourceUrl, "{self._resource_uri_prefix}")')
        if pkg_name is not None:
            if not _CEL_SAFE_PKG_RE.fullmatch(pkg_name):
                raise BackendQueryError(
                    f"[{self.name}] Unsafe package identifier {pkg_name!r} rejected by "
                    "filter guard."
                )
            clauses.append(f'dependencyPackageName="{pkg_name}"')
        return " AND ".join(clauses)

    def find_components(self, queries: Sequence[PackageQuery]) -> tuple[InventoryComponent, ...]:
        """Query Container Analysis ``occurrences`` for PACKAGE records matching ``queries``."""
        if not queries:
            return ()

        index = InMemoryComponentIndex()
        if not self._filter_by_package:
            for occ in self._fetch_occurrences(pkg_name=None):
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
            for occ in self._fetch_occurrences(pkg_name=lookup_name):
                index.add_components(
                    self._occurrence_to_components(
                        occ,
                        fallback_eco=fallback_eco,
                        fallback_ns=ns_hint,
                    )
                )

        return index.find_components(queries)

    def _fetch_occurrences(self, *, pkg_name: str | None) -> list[dict[str, Any]]:
        """Paginate ``GET /v1/projects/{project_id}/occurrences`` up to ``max_pages``."""
        endpoint = (
            f"{self._api_base_url}/v1/projects/{quote(self._project_id, safe='')}/occurrences"
        )
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._bearer_token}",
        }
        cel_filter = self._build_cel_filter(pkg_name)

        results: list[dict[str, Any]] = []
        page_token: str | None = None

        for _ in range(self._max_pages):
            params: dict[str, str] = {
                "filter": cel_filter,
                "pageSize": str(self._page_size),
            }
            if page_token is not None:
                params["pageToken"] = page_token

            status, _, body = read_bounded_response(
                self._client,
                "GET",
                endpoint,
                max_bytes=self._max_response_bytes,
                params=params,
                headers=headers,
                backend_name=self.name,
            )
            self._check_status(status, endpoint)
            doc = self._decode_json_dict(body, endpoint)

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

    def _decode_json_dict(self, body: bytes, url: str) -> dict[str, Any]:
        """Decode UTF-8 JSON object from GCP Container Analysis API."""
        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BackendQueryError(
                f"[{self.name}] Invalid JSON response from {url}: {exc}"
            ) from exc
        if not isinstance(decoded, dict):
            raise BackendQueryError(f"[{self.name}] Expected JSON object from {url}.")
        return decoded

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
        pkg_obj = occ.get("package")
        if not isinstance(pkg_obj, Mapping):
            return ()

        pkg_name = clean_optional_str(pkg_obj.get("name"))
        if pkg_name is None:
            return ()

        occ_name = clean_optional_str(occ.get("name")) or "occurrence"
        resource_uri = clean_optional_str(occ.get("resourceUri")) or clean_optional_str(
            occ.get("resourceUrl")
        )
        pkg_type_raw = (clean_optional_str(pkg_obj.get("packageType")) or "").upper()
        mapped_eco = _PACKAGE_TYPE_TO_ECOSYSTEM.get(pkg_type_raw)
        eco_hint = mapped_eco or fallback_eco

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

        # Collect version & OS CPE pairs from locations or top-level package.version.
        candidates: list[tuple[str, str | None]] = []
        raw_locations = pkg_obj.get("location")
        if isinstance(raw_locations, list):
            for loc in raw_locations:
                if not isinstance(loc, Mapping):
                    continue
                loc_ver = _format_version_obj(loc.get("version"))
                cpe_uri = clean_optional_str(loc.get("cpeUri"))
                if loc_ver is not None:
                    candidates.append((loc_ver, cpe_uri))

        if not candidates:
            top_ver = _format_version_obj(pkg_obj.get("version"))
            if top_ver is not None:
                candidates.append((top_ver, None))

        components: list[InventoryComponent] = []
        for ver_str, cpe_uri in candidates:
            raw_purl: str | None = None
            comp_eco = eco_hint
            comp_ns: str | None = fallback_ns

            os_info = _parse_os_cpe(cpe_uri)
            if os_info is not None and pkg_type_raw in {"", "OS"}:
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
