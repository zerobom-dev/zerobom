"""OWASP Dependency-Track REST API v1 inventory backend."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote

import httpx

from zerobom.backends._http import (
    DEFAULT_API_TIMEOUT_SECONDS,
    DEFAULT_MAX_RESPONSE_BYTES,
    MAX_API_TIMEOUT_SECONDS,
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
from zerobom.backends.base import BackendConfigError, BackendQueryError
from zerobom.backends.sbom_parser import (
    InMemoryComponentIndex,
    build_safe_metadata,
    clean_optional_str,
    make_inventory_component,
)
from zerobom.models import AssetRef, InventoryComponent, PackageQuery

_PROJECT_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_ALLOWED_CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "base_url",
        "api_key",
        "bearer_token",
        "project_uuid",
        "query_mode",
        "exclude_inactive_projects",
        "only_latest_project_versions",
        "page_size",
        "max_pages",
        "timeout_seconds",
        "max_response_bytes",
        "ca_bundle",
        "verify_tls",
        "allow_insecure_http",
    }
)


class DependencyTrackBackend:
    """Query-driven OWASP Dependency-Track REST API v1 inventory backend."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None = None,
        bearer_token: str | None = None,
        project_uuid: str | None = None,
        query_mode: Literal["coordinates", "purl"] = "coordinates",
        exclude_inactive_projects: bool = True,
        only_latest_project_versions: bool = False,
        page_size: int = 100,
        max_pages: int = 50,
        timeout_seconds: float = DEFAULT_API_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        ca_bundle: str | Path | None = None,
        verify_tls: bool = True,
        allow_insecure_http: bool = False,
        http_client: httpx.Client | None = None,
    ) -> None:
        """Initialize an OWASP Dependency-Track API v1 inventory backend.

        Args:
            base_url: Dependency-Track API root URL (e.g., ``https://dtrack.internal``).
            api_key: Dependency-Track ``X-Api-Key`` credential.
            bearer_token: Optional OIDC/JWT bearer credential (mutually exclusive with
                ``api_key``).
            project_uuid: Optional single Dependency-Track project UUID filter.
            query_mode: Lookup strategy (``"coordinates"`` using ``name``/``group`` or
                ``"purl"`` using canonical PURLs).
            exclude_inactive_projects: Exclude inactive projects when querying components.
            only_latest_project_versions: Restrict queries to latest project versions.
            page_size: API page size in ``1..1000``.
            max_pages: Maximum paginated pages per query in ``1..500`` before failing closed.
            timeout_seconds: HTTP request timeout in ``0.5..120.0`` seconds.
            max_response_bytes: Maximum response payload size per HTTP call.
            ca_bundle: Optional custom PEM CA bundle path for private internal PKI.
            verify_tls: Enable TLS certificate verification (recommended).
            allow_insecure_http: Explicit opt-in to permit ``http://`` URLs for local testing.
            http_client: Optional externally managed :class:`httpx.Client` (e.g., in tests).

        Raises:
            BackendConfigError: If URL, credentials, TLS options, or bounds are invalid.
        """
        if not isinstance(allow_insecure_http, bool):
            raise BackendConfigError("Configuration option 'allow_insecure_http' must be a bool.")
        if not isinstance(verify_tls, bool):
            raise BackendConfigError("Configuration option 'verify_tls' must be a bool.")
        if not isinstance(exclude_inactive_projects, bool):
            raise BackendConfigError(
                "Configuration option 'exclude_inactive_projects' must be a bool."
            )
        if not isinstance(only_latest_project_versions, bool):
            raise BackendConfigError(
                "Configuration option 'only_latest_project_versions' must be a bool."
            )

        self._base_url = validate_api_base_url(
            base_url,
            allow_insecure_http=allow_insecure_http,
            field_name="base_url",
        )

        if api_key is not None and bearer_token is not None:
            raise BackendConfigError("Specify either 'api_key' or 'bearer_token', not both.")
        if api_key is None and bearer_token is None:
            raise BackendConfigError(
                "DependencyTrackBackend requires either 'api_key' or 'bearer_token'."
            )

        self._api_key = (
            validate_no_control_chars(api_key, field_name="api_key", max_length=4096)
            if api_key is not None
            else None
        )
        self._bearer_token = (
            validate_no_control_chars(bearer_token, field_name="bearer_token", max_length=4096)
            if bearer_token is not None
            else None
        )

        self._project_uuid: str | None = None
        if project_uuid is not None:
            cleaned_uuid = validate_no_control_chars(
                project_uuid,
                field_name="project_uuid",
                max_length=128,
            )
            if not _PROJECT_ID_RE.fullmatch(cleaned_uuid):
                raise BackendConfigError(
                    "Configuration option 'project_uuid' contains invalid characters."
                )
            self._project_uuid = cleaned_uuid

        if query_mode not in ("coordinates", "purl"):
            raise BackendConfigError(
                f"Configuration option 'query_mode' must be 'coordinates' or 'purl', "
                f"got {query_mode!r}."
            )
        self._query_mode: Literal["coordinates", "purl"] = query_mode
        self._exclude_inactive_projects = exclude_inactive_projects
        self._only_latest_project_versions = only_latest_project_versions
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
    def from_config(cls, config: Mapping[str, Any]) -> DependencyTrackBackend:
        """Instantiate :class:`DependencyTrackBackend` from CLI/file configuration.

        Environment variable fallbacks: ``ZEROBOM_DT_URL``, ``ZEROBOM_DT_API_KEY``,
        and ``ZEROBOM_DT_BEARER_TOKEN``.
        """
        reject_unknown_config_keys(config, _ALLOWED_CONFIG_KEYS, backend_name="dependency_track")

        base_url = parse_optional_str_opt(
            config,
            "base_url",
            env_var="ZEROBOM_DT_URL",
            max_length=MAX_API_URL_LENGTH,
        )
        if base_url is None:
            raise BackendConfigError(
                "DependencyTrackBackend requires 'base_url' "
                "(or ZEROBOM_DT_URL environment variable)."
            )

        cfg_api_key = parse_optional_str_opt(config, "api_key", max_length=4096)
        cfg_bearer = parse_optional_str_opt(config, "bearer_token", max_length=4096)
        api_key = cfg_api_key
        bearer_token = cfg_bearer
        if api_key is None and bearer_token is None:
            raw_env_key = os.environ.get("ZEROBOM_DT_API_KEY")
            raw_env_bearer = os.environ.get("ZEROBOM_DT_BEARER_TOKEN")
            if raw_env_key and raw_env_key.strip():
                api_key = validate_no_control_chars(
                    raw_env_key,
                    field_name="ZEROBOM_DT_API_KEY",
                    max_length=4096,
                )
            if raw_env_bearer and raw_env_bearer.strip():
                bearer_token = validate_no_control_chars(
                    raw_env_bearer,
                    field_name="ZEROBOM_DT_BEARER_TOKEN",
                    max_length=4096,
                )

        raw_qmode = parse_optional_str_opt(config, "query_mode", max_length=32)
        qmode: Literal["coordinates", "purl"]
        if raw_qmode is None or raw_qmode == "coordinates":
            qmode = "coordinates"
        elif raw_qmode == "purl":
            qmode = "purl"
        else:
            raise BackendConfigError(
                f"Configuration option 'query_mode' must be 'coordinates' or 'purl', "
                f"got {raw_qmode!r}."
            )

        return cls(
            base_url=base_url,
            api_key=api_key,
            bearer_token=bearer_token,
            project_uuid=parse_optional_str_opt(config, "project_uuid", max_length=128),
            query_mode=qmode,
            exclude_inactive_projects=parse_bool_opt(
                config, "exclude_inactive_projects", default=True
            ),
            only_latest_project_versions=parse_bool_opt(
                config, "only_latest_project_versions", default=False
            ),
            page_size=parse_int_opt(config, "page_size", default=100, min_value=1, max_value=1000),
            max_pages=parse_int_opt(config, "max_pages", default=50, min_value=1, max_value=500),
            timeout_seconds=parse_float_opt(
                config,
                "timeout_seconds",
                default=DEFAULT_API_TIMEOUT_SECONDS,
                min_value=0.5,
                max_value=MAX_API_TIMEOUT_SECONDS,
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
        """Registered backend plugin identifier (``"dependency_track"``)."""
        return "dependency_track"

    def close(self) -> None:
        """Close the internally managed HTTP client connection pool."""
        if self._owns_client:
            self._client.close()

    def __repr__(self) -> str:
        """Return a redacted representation that never exposes API credentials."""
        auth_kind = "api_key" if self._api_key is not None else "bearer"
        return (
            f"DependencyTrackBackend(base_url={self._base_url!r}, "
            f"project_uuid={self._project_uuid!r}, auth={auth_kind!r})"
        )

    def find_components(self, queries: Sequence[PackageQuery]) -> tuple[InventoryComponent, ...]:
        """Query Dependency-Track ``/api/v1/component/identity`` for candidate packages.

        Args:
            queries: Normalized package queries built from an OSV advisory.

        Returns:
            Deduplicated :class:`InventoryComponent` entries matched via canonical PURL index.

        Raises:
            BackendQueryError: On HTTP failure, auth denial, redirect, pagination overflow,
                or malformed JSON responses.
        """
        if not queries:
            return ()

        unique_queries: list[PackageQuery] = []
        seen_keys: set[tuple[str, ...]] = set()
        for query in queries:
            if self._query_mode == "purl":
                key: tuple[str, ...] = (query.canonical_purl,)
            else:
                group = (
                    query.namespace
                    if query.namespace is not None and query.ecosystem not in {"deb", "rpm", "apk"}
                    else ""
                )
                key = (group, query.name)
            if key not in seen_keys:
                seen_keys.add(key)
                unique_queries.append(query)

        index = InMemoryComponentIndex()
        for query in unique_queries:
            index.add_components(self._query_single_purl(query))

        return index.find_components(queries)

    def _build_headers(self) -> dict[str, str]:
        """Construct authenticated request headers."""
        headers: dict[str, str] = {"Accept": "application/json"}
        if self._api_key is not None:
            headers["X-Api-Key"] = self._api_key
        elif self._bearer_token is not None:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        return headers

    def _query_single_purl(self, query: PackageQuery) -> tuple[InventoryComponent, ...]:
        """Paginate component identity hits using coordinate or canonical PURL lookups."""
        endpoint = f"{self._base_url}/api/v1/component/identity"
        headers = self._build_headers()

        collected: list[InventoryComponent] = []
        fetched_items = 0
        completed = False

        for page in range(1, self._max_pages + 1):
            params: dict[str, str] = {
                "pageNumber": str(page),
                "pageSize": str(self._page_size),
                "excludeInactiveProjects": "true" if self._exclude_inactive_projects else "false",
                "onlyLatestProjectVersions": (
                    "true" if self._only_latest_project_versions else "false"
                ),
            }
            if self._query_mode == "purl":
                params["purl"] = query.canonical_purl
            else:
                params["name"] = query.name
                if query.namespace is not None and query.ecosystem not in {"deb", "rpm", "apk"}:
                    params["group"] = query.namespace
            if self._project_uuid is not None:
                params["project"] = self._project_uuid

            status, resp_headers, body = read_bounded_response(
                self._client,
                "GET",
                endpoint,
                max_bytes=self._max_response_bytes,
                params=params,
                headers=headers,
                backend_name=self.name,
            )

            self._check_response_status(status, endpoint)
            items = self._decode_component_list(body, endpoint)
            for item in items:
                component = self._item_to_component(item, query)
                if component is not None:
                    collected.append(component)

            fetched_items += len(items)
            total_count = _parse_total_count(resp_headers)

            if not items or len(items) < self._page_size:
                completed = True
                break
            if total_count is not None and fetched_items >= total_count:
                completed = True
                break

        if not completed:
            raise BackendQueryError(
                f"[{self.name}] Pagination exceeded max_pages={self._max_pages} "
                f"for query {query.canonical_purl}."
            )

        return tuple(collected)

    def _check_response_status(self, status: int, url: str) -> None:
        """Fail closed on redirects, authentication rejections, rate limits, and server errors."""
        if status in REDIRECT_STATUS_CODES:
            raise BackendQueryError(
                f"[{self.name}] Unexpected HTTP redirect ({status}) from {url}; redirects disabled."
            )
        if status in (401, 403):
            raise BackendQueryError(
                f"[{self.name}] Authentication or RBAC authorization failed ({status}) at {url}."
            )
        if status == 429:
            raise BackendQueryError(f"[{self.name}] Rate limited (HTTP 429) by {url}.")
        if status != 200:
            raise BackendQueryError(
                f"[{self.name}] Dependency-Track API returned unexpected status {status} at {url}."
            )

    def _decode_component_list(self, body: bytes, url: str) -> list[dict[str, Any]]:
        """Decode UTF-8 JSON array response into validated mapping entries."""
        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise BackendQueryError(
                f"[{self.name}] Malformed JSON payload from {url}: {exc}"
            ) from exc

        if not isinstance(decoded, list):
            raise BackendQueryError(
                f"[{self.name}] Expected JSON array from {url}, got {type(decoded).__name__}."
            )
        return [entry for entry in decoded if isinstance(entry, dict)]

    def _item_to_component(
        self,
        item: Mapping[str, Any],
        query: PackageQuery,
    ) -> InventoryComponent | None:
        """Convert a Dependency-Track component JSON object into :class:`InventoryComponent`."""
        raw_project = item.get("project")
        project: Mapping[str, Any] = raw_project if isinstance(raw_project, Mapping) else {}

        project_uuid = clean_optional_str(project.get("uuid")) or self._project_uuid
        project_name = clean_optional_str(project.get("name"))
        project_version = clean_optional_str(project.get("version"))
        classifier = clean_optional_str(project.get("classifier"))
        component_uuid = clean_optional_str(item.get("uuid"))

        if project_uuid is not None:
            asset_id = f"dt-project:{project_uuid}"
            location: str | None = f"{self._base_url}/projects/{quote(project_uuid, safe='')}"
        elif project_name is not None and project_version is not None:
            asset_id = f"dt-project:{project_name}@{project_version}"
            location = None
        elif project_name is not None:
            asset_id = f"dt-project:{project_name}"
            location = None
        else:
            asset_id = "dt-project:unknown"
            location = None

        if project_name is not None and project_version is not None:
            scope: str | None = f"{project_name}:{project_version}"
        else:
            scope = project_name

        asset = AssetRef(
            asset_id=asset_id,
            asset_type="dependency_track_project",
            backend=self.name,
            scope=scope,
            location=location,
            metadata=build_safe_metadata(
                {
                    "project_uuid": project_uuid,
                    "project_name": project_name,
                    "project_version": project_version,
                    "classifier": classifier,
                    "component_uuid": component_uuid,
                }
            ),
        )

        return make_inventory_component(
            raw_name=item.get("name"),
            raw_version=item.get("version"),
            raw_purl=item.get("purl") or item.get("purlCoordinates"),
            ecosystem_hint=query.ecosystem,
            namespace_hint=item.get("group"),
            asset=asset,
            bom_ref=component_uuid,
        )


def _parse_total_count(headers: httpx.Headers) -> int | None:
    """Parse ``X-Total-Count`` response header when present and non-negative."""
    raw = headers.get("x-total-count")
    if raw is None:
        return None
    stripped = raw.strip()
    if stripped.isdigit():
        return int(stripped)
    return None
