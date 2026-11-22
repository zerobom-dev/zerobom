"""Azure Resource Graph software inventory backend plugin."""

from __future__ import annotations

import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import quote

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
from zerobom_azure._auth import AzureTokenProvider, resolve_azure_cloud_preset
from zerobom_azure._common import (
    build_azure_http_client,
    decode_json_dict,
    parse_azure_timespan_seconds,
    request_with_retry,
)

DEFAULT_AZURE_RM_URL = "https://management.azure.com"
_RESOURCE_GRAPH_API_VERSION = "2024-04-01"
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_MG_ID_RE = re.compile(r"^[A-Za-z0-9._()-]{1,90}$")
_KQL_SAFE_PKG_RE = re.compile(r"^[A-Za-z0-9._/@:+-]{1,256}$")
_DEBIAN_VER_RE = re.compile(r"(\d+)")
_MINOR_VER_RE = re.compile(r"(\d+\.\d+)")

_ALLOWED_CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "subscriptions",
        "management_groups",
        "tenant_scope",
        "cloud",
        "access_token",
        "use_default_credential",
        "api_base_url",
        "page_size",
        "max_pages",
        "max_retries",
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


def _map_os_platform_to_distro(os_platform: str | None) -> tuple[str, str, str] | None:
    """Map Defender ``osPlatform`` strings to ``(category, distro_ns, distro_release)``."""
    if not os_platform:
        return None
    lower = os_platform.strip().lower()
    if "windows" in lower:
        return ("windows", "microsoft", "windows")
    if "debian" in lower:
        m = _DEBIAN_VER_RE.search(lower)
        return ("deb", "debian", f"debian-{m.group(1)}" if m else "debian")
    if "ubuntu" in lower:
        m = _MINOR_VER_RE.search(lower) or _DEBIAN_VER_RE.search(lower)
        return ("deb", "ubuntu", f"ubuntu-{m.group(1)}" if m else "ubuntu")
    if "alpine" in lower:
        m = _MINOR_VER_RE.search(lower) or _DEBIAN_VER_RE.search(lower)
        return ("apk", "alpine", f"alpine-{m.group(1)}" if m else "alpine")
    if "redhat" in lower or "rhel" in lower:
        m = _DEBIAN_VER_RE.search(lower)
        return ("rpm", "redhat", f"rhel-{m.group(1)}" if m else "rhel")
    if "rocky" in lower:
        m = _DEBIAN_VER_RE.search(lower)
        return ("rpm", "rocky", f"rocky-{m.group(1)}" if m else "rocky")
    if "alma" in lower:
        m = _DEBIAN_VER_RE.search(lower)
        return ("rpm", "almalinux", f"almalinux-{m.group(1)}" if m else "almalinux")
    if "centos" in lower:
        m = _DEBIAN_VER_RE.search(lower)
        return ("rpm", "centos", f"centos-{m.group(1)}" if m else "centos")
    if "sles" in lower or "suse" in lower:
        m = _DEBIAN_VER_RE.search(lower)
        return ("rpm", "suse", f"sles-{m.group(1)}" if m else "sles")
    return None


def _kql_variants_for_query(query: PackageQuery) -> tuple[str, ...]:
    """Generate KQL-safe softwareName lookup variants (original + snake_case/hyphen swap)."""
    candidates = [
        query.name,
        query.name.replace("-", "_"),
        query.name.replace("_", "-"),
    ]
    seen: set[str] = set()
    ordered: list[str] = []
    for cand in candidates:
        if cand and cand not in seen:
            seen.add(cand)
            ordered.append(cand)
    return tuple(ordered)


class AzureResourceGraphBackend:
    """Query-driven Azure Resource Graph (Defender / VM & Container Software) backend."""

    def __init__(
        self,
        *,
        subscriptions: Sequence[str] = (),
        management_groups: Sequence[str] = (),
        tenant_scope: bool = False,
        cloud: str = "commercial",
        access_token: str | None = None,
        use_default_credential: bool | None = None,
        api_base_url: str | None = None,
        page_size: int = 100,
        max_pages: int = 50,
        max_retries: int = 3,
        timeout_seconds: float = DEFAULT_API_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        ca_bundle: str | Path | None = None,
        verify_tls: bool = True,
        allow_insecure_http: bool = False,
        http_client: httpx.Client | None = None,
        token_provider: AzureTokenProvider | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        """Initialize an Azure Resource Graph software inventory backend.

        Raises:
            BackendConfigError: If scopes, cloud preset, URL, credentials, TLS, or bounds fail.
        """
        if not isinstance(tenant_scope, bool):
            raise BackendConfigError("Configuration option 'tenant_scope' must be a bool.")
        if use_default_credential is not None and not isinstance(use_default_credential, bool):
            raise BackendConfigError(
                "Configuration option 'use_default_credential' must be a bool."
            )
        if not isinstance(verify_tls, bool):
            raise BackendConfigError("Configuration option 'verify_tls' must be a bool.")
        if not isinstance(allow_insecure_http, bool):
            raise BackendConfigError("Configuration option 'allow_insecure_http' must be a bool.")

        if isinstance(subscriptions, (str, bytes)) or not isinstance(subscriptions, Sequence):
            raise BackendConfigError("Configuration option 'subscriptions' must be a sequence.")
        if isinstance(management_groups, (str, bytes)) or not isinstance(
            management_groups, Sequence
        ):
            raise BackendConfigError("Configuration option 'management_groups' must be a sequence.")

        scope_count = int(bool(subscriptions)) + int(bool(management_groups)) + int(tenant_scope)
        if scope_count == 0:
            raise BackendConfigError(
                "AzureResourceGraphBackend requires 'subscriptions', 'management_groups', "
                "or 'tenant_scope=True'."
            )
        if scope_count > 1:
            raise BackendConfigError(
                "Specify only one of 'subscriptions', 'management_groups', or 'tenant_scope=True'."
            )

        if len(subscriptions) > 1000:
            raise BackendConfigError(
                "AzureResourceGraphBackend supports at most 1000 subscriptions."
            )
        if len(management_groups) > 10:
            raise BackendConfigError(
                "AzureResourceGraphBackend supports at most 10 management_groups."
            )

        cleaned_subs: list[str] = []
        for sub in subscriptions:
            val = validate_no_control_chars(sub, field_name="subscriptions", max_length=64)
            if not _UUID_RE.fullmatch(val):
                raise BackendConfigError(f"Invalid Azure subscription GUID: {sub!r}.")
            cleaned_subs.append(val)
        self._subscriptions = tuple(cleaned_subs)

        cleaned_mgs: list[str] = []
        for mg in management_groups:
            val = validate_no_control_chars(mg, field_name="management_groups", max_length=90)
            if not _MG_ID_RE.fullmatch(val):
                raise BackendConfigError(f"Invalid Azure management_group ID: {mg!r}.")
            cleaned_mgs.append(val)
        self._management_groups = tuple(cleaned_mgs)
        self._tenant_scope = tenant_scope

        preset = resolve_azure_cloud_preset(cloud)
        self._cloud = preset.name
        self._api_base_url = validate_api_base_url(
            api_base_url or preset.resource_manager_url,
            allow_insecure_http=allow_insecure_http,
            field_name="api_base_url",
        )
        self._token_provider = token_provider or AzureTokenProvider(
            access_token=access_token,
            scope=preset.resource_manager_scope,
            use_default_credential=use_default_credential,
            authority=preset.authority,
        )
        self._page_size = validate_bounded_int(
            page_size, field_name="page_size", min_value=1, max_value=1000
        )
        self._max_pages = validate_bounded_int(
            max_pages, field_name="max_pages", min_value=1, max_value=500
        )
        self._max_retries = validate_bounded_int(
            max_retries, field_name="max_retries", min_value=0, max_value=10
        )
        self._timeout_seconds = validate_timeout_seconds(timeout_seconds)
        self._max_response_bytes = validate_bounded_int(
            max_response_bytes,
            field_name="max_response_bytes",
            min_value=1024,
            max_value=100 * 1024 * 1024,
        )
        self._sleep_fn = sleep_fn

        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            verify_arg = resolve_tls_verify(verify_tls=verify_tls, ca_bundle=ca_bundle)
            self._client = build_azure_http_client(
                timeout_seconds=self._timeout_seconds,
                verify=verify_arg,
            )
            self._owns_client = True

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> AzureResourceGraphBackend:
        """Instantiate :class:`AzureResourceGraphBackend` from CLI or file config."""
        reject_unknown_config_keys(
            config, _ALLOWED_CONFIG_KEYS, backend_name="azure_resource_graph"
        )
        subs = parse_str_list_opt(config, "subscriptions", max_items=1000, max_item_length=64)
        mgs = parse_str_list_opt(config, "management_groups", max_items=10, max_item_length=90)
        tenant_scope = parse_bool_opt(config, "tenant_scope", default=False)

        if not subs and not mgs and not tenant_scope:
            env_sub = os.environ.get("ZEROBOM_AZURE_SUBSCRIPTION_ID")
            if env_sub and env_sub.strip():
                validated_env = validate_no_control_chars(
                    env_sub, field_name="ZEROBOM_AZURE_SUBSCRIPTION_ID", max_length=4096
                )
                subs = tuple(part.strip() for part in validated_env.split(",") if part.strip())

        if not subs and not mgs and not tenant_scope:
            raise BackendConfigError(
                "AzureResourceGraphBackend requires 'subscriptions', 'management_groups', "
                "'tenant_scope=True', or ZEROBOM_AZURE_SUBSCRIPTION_ID."
            )

        raw_use_dc = (
            parse_bool_opt(config, "use_default_credential", default=False)
            if "use_default_credential" in config and config["use_default_credential"] is not None
            else None
        )

        return cls(
            subscriptions=subs,
            management_groups=mgs,
            tenant_scope=tenant_scope,
            cloud=parse_optional_str_opt(config, "cloud", max_length=32) or "commercial",
            access_token=parse_optional_str_opt(config, "access_token", max_length=8192),
            use_default_credential=raw_use_dc,
            api_base_url=parse_optional_str_opt(
                config, "api_base_url", max_length=MAX_API_URL_LENGTH
            ),
            page_size=parse_int_opt(config, "page_size", default=100, min_value=1, max_value=1000),
            max_pages=parse_int_opt(config, "max_pages", default=50, min_value=1, max_value=500),
            max_retries=parse_int_opt(config, "max_retries", default=3, min_value=0, max_value=10),
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
            f"AzureResourceGraphBackend(cloud={self._cloud!r}, "
            f"subscriptions={len(self._subscriptions)}, "
            f"management_groups={len(self._management_groups)}, "
            f"tenant_scope={self._tenant_scope}, api_base_url={self._api_base_url!r})"
        )

    def _build_safe_kql(
        self, queries: Sequence[PackageQuery]
    ) -> tuple[str, dict[str, list[PackageQuery]]]:
        """Validate every queried package variant strictly against a KQL-safe allowlist."""
        lookup_map: dict[str, list[PackageQuery]] = {}
        safe_literals: list[str] = []
        seen_literals: set[str] = set()

        for query in queries:
            for variant in _kql_variants_for_query(query):
                if not _KQL_SAFE_PKG_RE.fullmatch(variant):
                    raise BackendQueryError(
                        f"[{self.name}] Unsafe package identifier {variant!r} "
                        "rejected by KQL guard."
                    )
                lower_var = variant.lower()
                lookup_map.setdefault(lower_var, []).append(query)
                if lower_var not in seen_literals:
                    seen_literals.add(lower_var)
                    safe_literals.append(f"'{variant}'")

        quoted_list = ", ".join(safe_literals)
        kql = (
            "securityresources "
            "| where type =~ 'microsoft.security/softwareinventories' "
            "| extend swName = tostring(properties.softwareName), "
            "swVersion = tostring(properties.version), "
            "swVendor = tostring(properties.vendor), "
            "osPlatform = tostring(properties.osPlatform), "
            "endOfSupportStatus = tostring(properties.endOfSupportStatus), "
            "deviceId = tostring(properties.deviceId), "
            "resourceId = coalesce(tostring(properties.azureVmId), "
            "tostring(properties.resourceId), id) "
            f"| where swName in~ ({quoted_list}) "
            "| project id, subscriptionId, location, resourceGroup, resourceType = type, "
            "resourceId, deviceId, softwareName = swName, softwareVersion = swVersion, "
            "softwareVendor = swVendor, osPlatform, endOfSupportStatus"
        )
        return kql, lookup_map

    def find_components(self, queries: Sequence[PackageQuery]) -> tuple[InventoryComponent, ...]:
        """Execute a quota-aware paginated KQL Resource Graph query for candidate software."""
        if not queries:
            return ()

        kql, lookup_map = self._build_safe_kql(queries)
        endpoint = f"{self._api_base_url}/providers/Microsoft.ResourceGraph/resources"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
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

            body_payload: dict[str, Any] = {
                "query": kql,
                "options": options,
            }
            if self._subscriptions:
                body_payload["subscriptions"] = list(self._subscriptions)
            elif self._management_groups:
                body_payload["managementGroups"] = list(self._management_groups)

            status, resp_headers, raw_resp = request_with_retry(
                self._client,
                "POST",
                endpoint,
                token_provider=self._token_provider,
                max_bytes=self._max_response_bytes,
                backend_name=self.name,
                params={"api-version": _RESOURCE_GRAPH_API_VERSION},
                headers=headers,
                json_body=body_payload,
                max_retries=self._max_retries,
                sleep_fn=self._sleep_fn,
            )
            self._check_status(status, endpoint)
            doc = decode_json_dict(raw_resp, endpoint, self.name)

            for row in _table_to_rows(doc.get("data")):
                comp = self._row_to_component(row, lookup_map)
                if comp is not None:
                    index.add_components((comp,))

            skip_token = clean_optional_str(doc.get("$skipToken"))
            if skip_token is None:
                completed = True
                break

            rem_raw = clean_optional_str(resp_headers.get("x-ms-user-quota-remaining"))
            if rem_raw is not None and rem_raw.lstrip("-").isdigit() and int(rem_raw) <= 0:
                reset_delay = parse_azure_timespan_seconds(
                    resp_headers.get("x-ms-user-quota-resets-after")
                )
                self._sleep_fn(reset_delay if reset_delay is not None else 5.0)

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

    def _row_to_component(
        self,
        row: Mapping[str, Any],
        lookup_map: Mapping[str, Sequence[PackageQuery]],
    ) -> InventoryComponent | None:
        """Convert one Resource Graph result row into :class:`InventoryComponent`."""
        sw_name = clean_optional_str(row.get("softwareName") or row.get("name"))
        sw_ver = clean_optional_str(row.get("softwareVersion") or row.get("version"))
        if sw_name is None or sw_ver is None:
            return None

        matching_queries = lookup_map.get(sw_name.lower(), ())
        distinct_ecosystems = {q.ecosystem for q in matching_queries}
        os_platform = clean_optional_str(row.get("osPlatform"))
        os_info = _map_os_platform_to_distro(os_platform)

        # Skip Defender Windows-only software records when querying strictly Linux OS ecosystems.
        if (
            os_info is not None
            and os_info[0] == "windows"
            and matching_queries
            and all(q.ecosystem in {"deb", "rpm", "apk"} for q in matching_queries)
        ):
            return None

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
                    "os_platform": os_platform,
                    "end_of_support_status": clean_optional_str(row.get("endOfSupportStatus")),
                    "device_id": clean_optional_str(row.get("deviceId")),
                    "assessment_id": clean_optional_str(row.get("id")),
                }
            ),
        )

        raw_purl = clean_optional_str(row.get("purl"))
        eco_hint = clean_optional_str(row.get("ecosystem"))
        ns_hint: str | None = None

        # Resolve canonical query package name before PURL synthesis so snake_case Defender
        # names (e.g. apache_http_server) match canonical OSV queries (apache-http-server).
        canonical_name = sw_name
        if matching_queries:
            for q in matching_queries:
                if q.name.lower() == sw_name.lower() or (
                    q.name.lower().replace("-", "_") == sw_name.lower()
                ):
                    canonical_name = q.name
                    break

        if len(distinct_ecosystems) == 1:
            only_query = matching_queries[0]
            if eco_hint is None:
                eco_hint = only_query.ecosystem
            ns_hint = only_query.namespace

        if raw_purl is None and os_info is not None and os_info[0] in {"deb", "rpm", "apk"}:
            purl_type, distro_ns, distro_rel = os_info
            if any(q.ecosystem == purl_type for q in matching_queries) or eco_hint == purl_type:
                eco_hint = purl_type
                ns_hint = distro_ns
                raw_purl = (
                    f"pkg:{purl_type}/{quote(distro_ns, safe='')}/"
                    f"{quote(canonical_name, safe='')}@{quote(sw_ver, safe='')}?distro={distro_rel}"
                )

        return make_inventory_component(
            raw_name=canonical_name,
            raw_version=sw_ver,
            raw_purl=raw_purl,
            ecosystem_hint=eco_hint,
            namespace_hint=ns_hint,
            asset=asset,
        )
