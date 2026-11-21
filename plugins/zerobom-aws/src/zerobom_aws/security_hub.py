"""AWS Security Hub v2 software inventory backend plugin."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from typing import Any

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError
from packageurl import PackageURL

from zerobom.backends import (
    BackendConfigError,
    BackendQueryError,
    InMemoryComponentIndex,
)
from zerobom.backends._http import (
    DEFAULT_API_TIMEOUT_SECONDS,
    parse_float_opt,
    parse_int_opt,
    parse_optional_str_opt,
    parse_str_list_opt,
    reject_unknown_config_keys,
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

_AWS_REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+$")
_AWS_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")

_GENERIC_PACKAGE_TYPES: frozenset[str] = frozenset(
    {"", "library", "application", "operating-system", "os", "binary"}
)
_PACKAGE_TYPE_TO_ECOSYSTEM: dict[str, str] = {
    "python": "pypi",
    "pypi": "pypi",
    "npm": "npm",
    "node_package": "npm",
    "node": "npm",
    "java": "maven",
    "jar": "maven",
    "maven": "maven",
    "go": "golang",
    "golang": "golang",
    "gomodule": "golang",
    "ruby": "gem",
    "gem": "gem",
    "rubygems": "gem",
    "rust": "cargo",
    "cargo": "cargo",
    "crate": "cargo",
    "php": "composer",
    "composer": "composer",
    "dotnet": "nuget",
    "dotnetcore": "nuget",
    "nuget": "nuget",
    "deb": "deb",
    "debian": "deb",
    "dpkg": "deb",
    "rpm": "rpm",
    "apk": "apk",
    "alpine": "apk",
}

_ALLOWED_CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "region_name",
        "profile_name",
        "account_ids",
        "resource_types",
        "package_types",
        "max_results",
        "max_pages",
        "max_software_entries",
        "timeout_seconds",
    }
)


def _lookup_names_for_query(query: PackageQuery) -> tuple[str, ...]:
    """Generate Security Hub ``PackageName`` lookup candidates for a canonical query."""
    candidates: list[str] = [query.name]
    if query.namespace:
        if query.ecosystem == "maven":
            candidates.append(f"{query.namespace}:{query.name}")
        elif query.ecosystem in {"npm", "golang"}:
            candidates.append(f"{query.namespace}/{query.name}")
    seen: set[str] = set()
    ordered: list[str] = []
    for cand in candidates:
        if cand not in seen:
            seen.add(cand)
            ordered.append(cand)
    return tuple(ordered)


def _map_package_type(raw_package_type: Any) -> str | None:
    """Resolve an AWS Security Hub ``PackageType`` field to a canonical ecosystem hint."""
    cleaned = (clean_optional_str(raw_package_type) or "").lower()
    if not cleaned or cleaned in _GENERIC_PACKAGE_TYPES:
        return None
    return _PACKAGE_TYPE_TO_ECOSYSTEM.get(cleaned)


def _build_concrete_purl(
    *,
    pkg_name: str,
    pkg_ver: str,
    pkg_type: str,
    ecosystem_hint: str | None,
    namespace_hint: str | None,
) -> str | None:
    """Build a versioned PURL when Security Hub reports a concrete ecosystem type."""
    if ecosystem_hint is None or pkg_type.strip().lower() not in _PACKAGE_TYPE_TO_ECOSYSTEM:
        return None
    purl_ns = namespace_hint
    purl_name = pkg_name
    if ecosystem_hint == "maven" and ":" in pkg_name and purl_ns is None:
        purl_ns, _, purl_name = pkg_name.partition(":")
    elif ecosystem_hint in {"npm", "golang"} and "/" in pkg_name and purl_ns is None:
        purl_ns, _, purl_name = pkg_name.rsplit("/", 1)
    try:
        return str(
            PackageURL(type=ecosystem_hint, namespace=purl_ns, name=purl_name, version=pkg_ver)
        )
    except ValueError:
        return None


class AwsSecurityHubBackend:
    """Query-driven AWS Security Hub v2 (``GetSoftwareV2``) inventory backend."""

    def __init__(
        self,
        *,
        region_name: str | None = None,
        profile_name: str | None = None,
        account_ids: Sequence[str] = (),
        resource_types: Sequence[str] = (),
        package_types: Sequence[str] = (),
        max_results: int = 100,
        max_pages: int = 50,
        max_software_entries: int = 200,
        timeout_seconds: float = DEFAULT_API_TIMEOUT_SECONDS,
        client: Any | None = None,
    ) -> None:
        """Initialize an AWS Security Hub v2 software inventory backend.

        Args:
            region_name: AWS Region hosting Security Hub (falls back to ``AWS_REGION`` or SDK
                default profile resolution).
            profile_name: Optional AWS shared config/credentials profile name.
            account_ids: Optional 12-digit AWS account IDs to filter queried software/resources.
            resource_types: Optional Security Hub resource types (e.g., ``AwsEc2Instance``).
            package_types: Optional Security Hub package types (e.g., ``application``, ``library``).
            max_results: Per-page ``MaxResults`` limit in ``1..100``.
            max_pages: Maximum paginated ``NextToken`` hops per query in ``1..500``.
            max_software_entries: Maximum distinct ``SoftwareResult`` tuples expanded via
                ``GetSoftwareResourcesV2`` per ``find_components`` batch (``1..2000``).
            timeout_seconds: Botocore connect/read timeout in ``0.5..120.0`` seconds.
            client: Optional pre-built boto3 Security Hub client (for tests/mocking).

        Raises:
            BackendConfigError: If AWS regions, account IDs, or numeric limits are invalid.
        """
        self._region_name: str | None = None
        if region_name is not None:
            cleaned_region = validate_no_control_chars(
                region_name, field_name="region_name", max_length=64
            )
            if not _AWS_REGION_RE.fullmatch(cleaned_region):
                raise BackendConfigError(f"Invalid AWS region_name: {region_name!r}.")
            self._region_name = cleaned_region

        self._profile_name: str | None = (
            validate_no_control_chars(profile_name, field_name="profile_name", max_length=128)
            if profile_name is not None
            else None
        )

        validated_accounts: list[str] = []
        for raw_acc in account_ids:
            acc = validate_no_control_chars(raw_acc, field_name="account_ids", max_length=12)
            if not _AWS_ACCOUNT_RE.fullmatch(acc):
                raise BackendConfigError(f"Invalid 12-digit AWS account_id: {raw_acc!r}.")
            validated_accounts.append(acc)
        self._account_ids = tuple(validated_accounts)

        self._resource_types = tuple(
            validate_no_control_chars(rt, field_name="resource_types", max_length=128)
            for rt in resource_types
        )
        self._package_types = tuple(
            validate_no_control_chars(pt, field_name="package_types", max_length=64)
            for pt in package_types
        )

        self._max_results = validate_bounded_int(
            max_results, field_name="max_results", min_value=1, max_value=100
        )
        self._max_pages = validate_bounded_int(
            max_pages, field_name="max_pages", min_value=1, max_value=500
        )
        self._max_software_entries = validate_bounded_int(
            max_software_entries, field_name="max_software_entries", min_value=1, max_value=2000
        )
        self._timeout_seconds = validate_timeout_seconds(timeout_seconds)

        if client is not None:
            self._client = client
            self._owns_client = False
        else:
            session = boto3.Session(
                region_name=self._region_name,
                profile_name=self._profile_name,
            )
            boto_cfg = BotoConfig(
                connect_timeout=self._timeout_seconds,
                read_timeout=self._timeout_seconds,
                retries={"max_attempts": 3, "mode": "standard"},
            )
            self._client = session.client("securityhub", config=boto_cfg)
            self._owns_client = True

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> AwsSecurityHubBackend:
        """Instantiate :class:`AwsSecurityHubBackend` from CLI options or YAML/JSON config."""
        reject_unknown_config_keys(config, _ALLOWED_CONFIG_KEYS, backend_name="aws_security_hub")
        region = parse_optional_str_opt(config, "region_name", max_length=64)
        if region is None:
            raw_env_region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
            if raw_env_region and raw_env_region.strip():
                region = validate_no_control_chars(
                    raw_env_region, field_name="AWS_REGION", max_length=64
                )

        return cls(
            region_name=region,
            profile_name=parse_optional_str_opt(config, "profile_name", max_length=128),
            account_ids=parse_str_list_opt(
                config, "account_ids", max_items=100, max_item_length=12
            ),
            resource_types=parse_str_list_opt(
                config, "resource_types", max_items=50, max_item_length=128
            ),
            package_types=parse_str_list_opt(
                config, "package_types", max_items=20, max_item_length=64
            ),
            max_results=parse_int_opt(
                config, "max_results", default=100, min_value=1, max_value=100
            ),
            max_pages=parse_int_opt(config, "max_pages", default=50, min_value=1, max_value=500),
            max_software_entries=parse_int_opt(
                config, "max_software_entries", default=200, min_value=1, max_value=2000
            ),
            timeout_seconds=parse_float_opt(
                config,
                "timeout_seconds",
                default=DEFAULT_API_TIMEOUT_SECONDS,
                min_value=0.5,
                max_value=120.0,
            ),
        )

    @property
    def name(self) -> str:
        """Registered backend plugin identifier (``"aws_security_hub"``)."""
        return "aws_security_hub"

    def close(self) -> None:
        """Close the internally managed boto3 Security Hub client."""
        if self._owns_client:
            close_fn = getattr(self._client, "close", None)
            if callable(close_fn):
                close_fn()

    def __repr__(self) -> str:
        """Return a redacted summary without exposing AWS credentials."""
        return (
            f"AwsSecurityHubBackend(region_name={self._region_name!r}, "
            f"accounts={len(self._account_ids)}, max_results={self._max_results})"
        )

    def _build_scope_filters(self) -> list[dict[str, Any]]:
        """Construct Security Hub v2 composite scope filters for account/resource/package."""
        filters: list[dict[str, Any]] = []
        if self._account_ids:
            filters.append(
                {
                    "StringFilters": [
                        {
                            "FieldName": "AccountId",
                            "Filter": {"Value": acc, "Comparison": "EQUALS"},
                        }
                        for acc in self._account_ids
                    ],
                    "Operator": "OR",
                }
            )
        if self._resource_types:
            filters.append(
                {
                    "StringFilters": [
                        {
                            "FieldName": "ResourceType",
                            "Filter": {"Value": rt, "Comparison": "EQUALS"},
                        }
                        for rt in self._resource_types
                    ],
                    "Operator": "OR",
                }
            )
        if self._package_types:
            filters.append(
                {
                    "StringFilters": [
                        {
                            "FieldName": "PackageType",
                            "Filter": {"Value": pt, "Comparison": "EQUALS"},
                        }
                        for pt in self._package_types
                    ],
                    "Operator": "OR",
                }
            )
        return filters

    def find_components(self, queries: Sequence[PackageQuery]) -> tuple[InventoryComponent, ...]:
        """Query Security Hub ``GetSoftwareV2`` and ``GetSoftwareResourcesV2`` for package hits.

        Args:
            queries: Canonical package descriptors derived from an OSV advisory.

        Returns:
            Normalized :class:`InventoryComponent` records bound to AWS resource ``AssetRef``s.

        Raises:
            BackendQueryError: On AWS API errors or pagination limit exhaustion.
        """
        if not queries:
            return ()

        lookup_to_queries: dict[str, list[PackageQuery]] = {}
        for query in queries:
            for lookup_name in _lookup_names_for_query(query):
                lookup_to_queries.setdefault(lookup_name, []).append(query)

        index = InMemoryComponentIndex()
        seen_software: set[tuple[str, str, str]] = set()
        expanded_entries = 0
        scope_filters = self._build_scope_filters()

        for lookup_name, matching_queries in lookup_to_queries.items():
            software_items = self._paginate_software(lookup_name, scope_filters)

            for sw in software_items:
                pkg_name = clean_optional_str(sw.get("PackageName"))
                pkg_ver = clean_optional_str(sw.get("PackageVersion"))
                pkg_type = clean_optional_str(sw.get("PackageType")) or ""
                if pkg_name is None or pkg_ver is None:
                    continue
                if sw.get("ResourceCount") == 0:
                    continue

                sw_key = (pkg_name, pkg_ver, pkg_type)
                if sw_key in seen_software:
                    continue
                if expanded_entries >= self._max_software_entries:
                    raise BackendQueryError(
                        f"[{self.name}] Software result expansion exceeded "
                        f"max_software_entries={self._max_software_entries}."
                    )
                seen_software.add(sw_key)
                expanded_entries += 1

                mapped_eco = _map_package_type(pkg_type)
                distinct_ecosystems = {q.ecosystem for q in matching_queries}
                if mapped_eco is not None:
                    ecosystem_hint: str | None = mapped_eco
                    matched_eco_query = next(
                        (q for q in matching_queries if q.ecosystem == mapped_eco), None
                    )
                    namespace_hint = (
                        matched_eco_query.namespace
                        if matched_eco_query is not None and pkg_name == matched_eco_query.name
                        else None
                    )
                elif len(distinct_ecosystems) == 1:
                    only_query = matching_queries[0]
                    ecosystem_hint = only_query.ecosystem
                    namespace_hint = only_query.namespace if pkg_name == only_query.name else None
                else:
                    ecosystem_hint = None
                    namespace_hint = None

                resources = self._paginate_software_resources(
                    package_name=pkg_name,
                    package_type=pkg_type or "library",
                    package_version=pkg_ver,
                    scope_filters=scope_filters,
                )
                for res in resources:
                    comp = self._resource_to_component(
                        pkg_name=pkg_name,
                        pkg_ver=pkg_ver,
                        pkg_type=pkg_type,
                        ecosystem_hint=ecosystem_hint,
                        namespace_hint=namespace_hint,
                        resource=res,
                    )
                    if comp is not None:
                        index.add_components((comp,))

        return index.find_components(queries)

    def _paginate_software(
        self,
        lookup_name: str,
        scope_filters: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Paginate ``GetSoftwareV2`` up to ``max_pages``."""
        composite = [
            {
                "StringFilters": [
                    {
                        "FieldName": "PackageName",
                        "Filter": {"Value": lookup_name, "Comparison": "EQUALS"},
                    }
                ],
                "Operator": "AND",
            },
            *scope_filters,
        ]
        items: list[dict[str, Any]] = []
        next_token: str | None = None

        for _ in range(self._max_pages):
            kwargs: dict[str, Any] = {
                "Filters": {
                    "CompositeFilters": composite,
                    "CompositeOperator": "AND",
                },
                "MaxResults": self._max_results,
            }
            if next_token is not None:
                kwargs["NextToken"] = next_token

            try:
                response = self._client.get_software_v2(**kwargs)
            except (ClientError, BotoCoreError) as exc:
                raise BackendQueryError(
                    f"[{self.name}] Security Hub GetSoftwareV2 failed for {lookup_name!r}: {exc}"
                ) from exc

            raw_software = response.get("Software")
            if isinstance(raw_software, list):
                for entry in raw_software:
                    if isinstance(entry, Mapping):
                        items.append(dict(entry))

            next_token = clean_optional_str(response.get("NextToken"))
            if next_token is None:
                return items

        raise BackendQueryError(
            f"[{self.name}] GetSoftwareV2 pagination exceeded max_pages={self._max_pages}."
        )

    def _paginate_software_resources(
        self,
        *,
        package_name: str,
        package_type: str,
        package_version: str,
        scope_filters: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Paginate ``GetSoftwareResourcesV2`` up to ``max_pages``."""
        resources: list[dict[str, Any]] = []
        next_token: str | None = None

        for _ in range(self._max_pages):
            kwargs: dict[str, Any] = {
                "PackageName": package_name,
                "PackageType": package_type,
                "PackageVersion": package_version,
                "MaxResults": self._max_results,
            }
            if scope_filters:
                kwargs["Filters"] = {
                    "CompositeFilters": scope_filters,
                    "CompositeOperator": "AND",
                }
            if next_token is not None:
                kwargs["NextToken"] = next_token

            try:
                response = self._client.get_software_resources_v2(**kwargs)
            except (ClientError, BotoCoreError) as exc:
                raise BackendQueryError(
                    f"[{self.name}] Security Hub GetSoftwareResourcesV2 failed for "
                    f"{package_name}@{package_version}: {exc}"
                ) from exc

            raw_resources = response.get("SoftwareResources")
            if isinstance(raw_resources, list):
                for entry in raw_resources:
                    if isinstance(entry, Mapping):
                        resources.append(dict(entry))

            next_token = clean_optional_str(response.get("NextToken"))
            if next_token is None:
                return resources

        raise BackendQueryError(
            f"[{self.name}] GetSoftwareResourcesV2 pagination exceeded max_pages={self._max_pages}."
        )

    def _resource_to_component(
        self,
        *,
        pkg_name: str,
        pkg_ver: str,
        pkg_type: str,
        ecosystem_hint: str | None,
        namespace_hint: str | None,
        resource: Mapping[str, Any],
    ) -> InventoryComponent | None:
        """Convert one ``SoftwareResourceResult`` entry into an :class:`InventoryComponent`."""
        account_id = clean_optional_str(resource.get("AccountId"))
        owner_account = clean_optional_str(resource.get("ResourceOwnerAccountId"))
        owner_org = clean_optional_str(resource.get("ResourceOwnerOrgId"))
        region = clean_optional_str(resource.get("Region"))
        native_region = clean_optional_str(resource.get("ResourceRegion"))
        resource_type = clean_optional_str(resource.get("ResourceType")) or "aws_resource"
        resource_id = clean_optional_str(resource.get("ResourceId"))

        asset_id = (
            resource_id
            or f"aws-resource:{account_id or 'unknown'}:{region or 'unknown'}:{resource_type}"
        )
        asset = AssetRef(
            asset_id=asset_id,
            asset_type=resource_type,
            backend=self.name,
            scope=owner_account or account_id,
            location=native_region or region,
            metadata=build_safe_metadata(
                {
                    "account_id": account_id,
                    "region": region,
                    "resource_provider": resource.get("ResourceProvider"),
                    "resource_owner_account_id": owner_account,
                    "resource_owner_org_id": owner_org,
                    "cloud_partition": resource.get("ResourceCloudPartition"),
                    "package_type": pkg_type,
                }
            ),
        )

        raw_purl = _build_concrete_purl(
            pkg_name=pkg_name,
            pkg_ver=pkg_ver,
            pkg_type=pkg_type,
            ecosystem_hint=ecosystem_hint,
            namespace_hint=namespace_hint,
        )
        return make_inventory_component(
            raw_name=pkg_name,
            raw_version=pkg_ver,
            raw_purl=raw_purl,
            ecosystem_hint=ecosystem_hint,
            namespace_hint=namespace_hint,
            asset=asset,
        )
