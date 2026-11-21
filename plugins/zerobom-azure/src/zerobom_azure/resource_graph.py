"""Azure Resource Graph software inventory backend plugin."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx

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
    parse_str_list_opt,
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
from zerobom_azure._auth import AZURE_MGMT_SCOPE, resolve_azure_bearer_token

DEFAULT_AZURE_RM_URL = "https://management.azure.com"
_RESOURCE_GRAPH_API_VERSION = "2022-10-01"
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_KQL_SAFE_PKG_RE = re.compile(r"^[A-Za-z0-9._/@:+-]{1,256}$")

_ALLOWED_CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "subscriptions",
        "access_token",
        "use_default_credential",
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


def _table_to_rows(data: Any) -> list[dict[str, Any]]:
    """Normalize Azure Resource Graph ``objectArray`` or ``table`` data into dict rows."""
    if isinstance(data, list):
        return [dict(item) for item in data if isinstance(item, Mapping)]
    if isinstance(data, Mapping):
        cols = data.get("columns")
        rows = data.get("rows")
        if not isinstance(cols, list) or not isinstance(rows, list):
            return []
        col_names: list[str] = []
        for i, col in enumerate(cols):
            raw_col = col.get("name") if isinstance(col, Mapping) else None
            col_names.append(raw_col if isinstance(raw_col, str) else f"col_{i}")
        normalized: list[dict[str, Any]] = []
        for raw_row in rows:
            if not isinstance(raw_row, Sequence) or isinstance(raw_row, (str, bytes)):
                continue
            normalized.append(dict(zip(col_names, raw_row, strict=False)))
        return normalized
    return []


class AzureResourceGraphBackend:
    """Query-driven Azure Resource Graph (Defender / VM & Container Software) backend."""

    def __init__(
        self,
        *,
        subscriptions: Sequence[str],
        access_token: str | None = None,
        use_default_credential: bool = False,
        api_base_url: str = DEFAULT_AZURE_RM_URL,
        page_size: int = 100,
        max_pages: int = 50,
        timeout_seconds: float = DEFAULT_API_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        ca_bundle: str | Path | None = None,
        verify_tls: bool = True,
        allow_insecure_http: bool = False,
        http_client: httpx.Client | None = None,
    ) -> None:
        """Initialize an Azure Resource Graph software inventory backend.

        Raises:
            BackendConfigError: If subscription IDs, URL, credentials, TLS, or bounds fail.
        """
        if not isinstance(use_default_credential, bool):
            raise BackendConfigError(
                "Configuration option 'use_default_credential' must be a bool."
            )
        if not isinstance(verify_tls, bool):
            raise BackendConfigError("Configuration option 'verify_tls' must be a bool.")
        if not isinstance(allow_insecure_http, bool):
            raise BackendConfigError("Configuration option 'allow_insecure_http' must be a bool.")

        if isinstance(subscriptions, (str, bytes)) or not isinstance(subscriptions, Sequence):
            raise BackendConfigError("Configuration option 'subscriptions' must be a sequence.")
        if not subscriptions or len(subscriptions) > 100:
            raise BackendConfigError(
                "AzureResourceGraphBackend requires between 1 and 100 subscription IDs."
            )

        cleaned_subs: list[str] = []
        for sub in subscriptions:
            val = validate_no_control_chars(sub, field_name="subscriptions", max_length=64)
            if not _UUID_RE.fullmatch(val):
                raise BackendConfigError(f"Invalid Azure subscription GUID: {sub!r}.")
            cleaned_subs.append(val)
        self._subscriptions = tuple(cleaned_subs)

        self._api_base_url = validate_api_base_url(
            api_base_url,
            allow_insecure_http=allow_insecure_http,
            field_name="api_base_url",
        )
        self._bearer_token = resolve_azure_bearer_token(
            access_token,
            scope=AZURE_MGMT_SCOPE,
            use_default_credential=use_default_credential,
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
    def from_config(cls, config: Mapping[str, Any]) -> AzureResourceGraphBackend:
        """Instantiate :class:`AzureResourceGraphBackend` from CLI or file config."""
        reject_unknown_config_keys(
            config, _ALLOWED_CONFIG_KEYS, backend_name="azure_resource_graph"
        )
        subs = parse_str_list_opt(config, "subscriptions", max_items=100, max_item_length=64)
        if not subs:
            env_sub = os.environ.get("ZEROBOM_AZURE_SUBSCRIPTION_ID")
            if env_sub and env_sub.strip():
                validated_env = validate_no_control_chars(
                    env_sub, field_name="ZEROBOM_AZURE_SUBSCRIPTION_ID", max_length=4096
                )
                subs = tuple(part.strip() for part in validated_env.split(",") if part.strip())
        if not subs:
            raise BackendConfigError(
                "AzureResourceGraphBackend requires 'subscriptions' "
                "or ZEROBOM_AZURE_SUBSCRIPTION_ID."
            )

        return cls(
            subscriptions=subs,
            access_token=parse_optional_str_opt(config, "access_token", max_length=8192),
            use_default_credential=parse_bool_opt(config, "use_default_credential", default=False),
            api_base_url=parse_optional_str_opt(
                config, "api_base_url", max_length=MAX_API_URL_LENGTH
            )
            or DEFAULT_AZURE_RM_URL,
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
        """Registered backend plugin identifier (``"azure_resource_graph"``)."""
        return "azure_resource_graph"

    def close(self) -> None:
        """Close the internally managed HTTP client session."""
        if self._owns_client:
            self._client.close()

    def __repr__(self) -> str:
        """Return a redacted summary without leaking Azure credentials."""
        return (
            f"AzureResourceGraphBackend(subscriptions={len(self._subscriptions)}, "
            f"api_base_url={self._api_base_url!r})"
        )

    def _build_safe_kql(
        self, queries: Sequence[PackageQuery]
    ) -> tuple[str, dict[str, PackageQuery]]:
        """Validate every queried package name strictly against a KQL-safe allowlist."""
        lookup_map: dict[str, PackageQuery] = {}
        safe_literals: list[str] = []

        for query in queries:
            if not _KQL_SAFE_PKG_RE.fullmatch(query.name):
                raise BackendQueryError(
                    f"[{self.name}] Unsafe package identifier {query.name!r} rejected by KQL guard."
                )
            lower_name = query.name.lower()
            if lower_name not in lookup_map:
                lookup_map[lower_name] = query
                safe_literals.append(f"'{query.name}'")

        quoted_list = ", ".join(safe_literals)
        kql = (
            "securityresources "
            "| where type =~ 'microsoft.security/softwareinventories' "
            "| extend swName = tostring(properties.softwareName), "
            "swVersion = tostring(properties.version), "
            "swVendor = tostring(properties.vendor), "
            "osPlatform = tostring(properties.osPlatform), "
            "resourceId = coalesce(tostring(properties.azureVmId), id) "
            f"| where swName in~ ({quoted_list}) "
            "| project id, subscriptionId, location, resourceGroup, resourceType = type, "
            "resourceId, softwareName = swName, softwareVersion = swVersion, "
            "softwareVendor = swVendor, osPlatform"
        )
        return kql, lookup_map

    def find_components(self, queries: Sequence[PackageQuery]) -> tuple[InventoryComponent, ...]:
        """Execute a paginated KQL Resource Graph query for candidate software packages."""
        if not queries:
            return ()

        kql, lookup_map = self._build_safe_kql(queries)
        endpoint = f"{self._api_base_url}/providers/Microsoft.ResourceGraph/resources"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._bearer_token}",
        }

        index = InMemoryComponentIndex()
        skip_token: str | None = None
        completed = False

        for _ in range(self._max_pages):
            options: dict[str, Any] = {
                "$top": self._page_size,
                "resultFormat": "objectArray",
            }
            if skip_token is not None:
                options["$skipToken"] = skip_token

            body_payload = {
                "subscriptions": list(self._subscriptions),
                "query": kql,
                "options": options,
            }

            status, _, raw_resp = read_bounded_response(
                self._client,
                "POST",
                endpoint,
                max_bytes=self._max_response_bytes,
                params={"api-version": _RESOURCE_GRAPH_API_VERSION},
                headers=headers,
                json_body=body_payload,
                backend_name=self.name,
            )
            self._check_status(status, endpoint)
            doc = self._decode_json_dict(raw_resp, endpoint)

            for row in _table_to_rows(doc.get("data")):
                comp = self._row_to_component(row, lookup_map)
                if comp is not None:
                    index.add_components((comp,))

            skip_token = clean_optional_str(doc.get("$skipToken"))
            if skip_token is None:
                completed = True
                break

        if not completed:
            raise BackendQueryError(
                f"[{self.name}] Azure Resource Graph pagination exceeded "
                f"max_pages={self._max_pages}."
            )

        return index.find_components(queries)

    def _check_status(self, status: int, url: str) -> None:
        """Fail closed on redirects, Azure RBAC denials, throttling, and API errors."""
        if status in REDIRECT_STATUS_CODES:
            raise BackendQueryError(
                f"[{self.name}] Unexpected HTTP redirect ({status}) from {url}; redirects disabled."
            )
        if status in (401, 403):
            raise BackendQueryError(
                f"[{self.name}] Azure authentication/RBAC authorization denied ({status}) at {url}."
            )
        if status == 429:
            raise BackendQueryError(f"[{self.name}] Azure Resource Graph throttled (429) at {url}.")
        if status != 200:
            raise BackendQueryError(
                f"[{self.name}] Azure Resource Graph returned unexpected status {status} at {url}."
            )

    def _decode_json_dict(self, body: bytes, url: str) -> dict[str, Any]:
        """Decode UTF-8 JSON object from Azure Resource Graph REST API."""
        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BackendQueryError(
                f"[{self.name}] Invalid JSON response from {url}: {exc}"
            ) from exc
        if not isinstance(decoded, dict):
            raise BackendQueryError(f"[{self.name}] Expected JSON object from {url}.")
        return decoded

    def _row_to_component(
        self,
        row: Mapping[str, Any],
        lookup_map: Mapping[str, PackageQuery],
    ) -> InventoryComponent | None:
        """Convert one Resource Graph result row into :class:`InventoryComponent`."""
        sw_name = clean_optional_str(row.get("softwareName") or row.get("name"))
        sw_ver = clean_optional_str(row.get("softwareVersion") or row.get("version"))
        if sw_name is None or sw_ver is None:
            return None

        matched_query = lookup_map.get(sw_name.lower())
        resource_id = clean_optional_str(row.get("resourceId") or row.get("id")) or "azure-resource"
        resource_type = (
            clean_optional_str(row.get("resourceType") or row.get("type")) or "azure_resource"
        )
        sub_id = clean_optional_str(row.get("subscriptionId"))
        location = clean_optional_str(row.get("location"))

        asset = AssetRef(
            asset_id=resource_id,
            asset_type=resource_type,
            backend=self.name,
            scope=sub_id,
            location=location,
            metadata=build_safe_metadata(
                {
                    "subscription_id": sub_id,
                    "resource_group": clean_optional_str(row.get("resourceGroup")),
                    "software_vendor": clean_optional_str(row.get("softwareVendor")),
                    "os_platform": clean_optional_str(row.get("osPlatform")),
                    "assessment_id": clean_optional_str(row.get("id")),
                }
            ),
        )

        return make_inventory_component(
            raw_name=sw_name,
            raw_version=sw_ver,
            raw_purl=row.get("purl"),
            ecosystem_hint=clean_optional_str(row.get("ecosystem"))
            or (matched_query.ecosystem if matched_query else None),
            namespace_hint=matched_query.namespace if matched_query else None,
            asset=asset,
        )
