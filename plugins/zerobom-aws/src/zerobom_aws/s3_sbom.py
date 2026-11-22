"""Amazon S3 CycloneDX & SPDX SBOM inventory backend plugin."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from zerobom.backends import BackendConfigError, InMemoryComponentIndex
from zerobom.backends._http import (
    DEFAULT_API_TIMEOUT_SECONDS,
    MAX_API_URL_LENGTH,
    parse_bool_opt,
    parse_float_opt,
    parse_int_opt,
    parse_optional_str_opt,
    parse_str_list_opt,
    reject_unknown_config_keys,
    validate_bounded_int,
    validate_no_control_chars,
    validate_timeout_seconds,
)
from zerobom.backends.sbom_parser import MAX_SBOM_FILE_BYTES
from zerobom.models import InventoryComponent, PackageQuery
from zerobom_aws._common import (
    DEFAULT_SBOM_SUFFIXES,
    load_s3_sbom_prefix,
    validate_s3_bucket,
    validate_s3_prefix,
)
from zerobom_aws._session import (
    build_aws_client,
    resolve_env_aws_region,
    validate_aws_account_id,
    validate_aws_region,
)

_ALLOWED_CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "bucket",
        "prefix",
        "suffixes",
        "region_name",
        "profile_name",
        "role_arn",
        "external_id",
        "role_session_name",
        "endpoint_url",
        "allow_insecure_http",
        "expected_bucket_owner",
        "max_objects",
        "max_pages",
        "max_sbom_bytes",
        "max_concurrency",
        "max_retries",
        "timeout_seconds",
        "skip_archived",
        "strict",
    }
)


class S3SbomBackend:
    """Amazon S3 CycloneDX & SPDX JSON SBOM prefix inventory backend."""

    def __init__(
        self,
        *,
        bucket: str,
        prefix: str = "",
        suffixes: Sequence[str] = DEFAULT_SBOM_SUFFIXES,
        region_name: str | None = None,
        profile_name: str | None = None,
        role_arn: str | None = None,
        external_id: str | None = None,
        role_session_name: str = "zerobom-s3-sbom",
        endpoint_url: str | None = None,
        allow_insecure_http: bool = False,
        expected_bucket_owner: str | None = None,
        max_objects: int = 500,
        max_pages: int = 50,
        max_sbom_bytes: int = MAX_SBOM_FILE_BYTES,
        max_concurrency: int = 8,
        max_retries: int = 3,
        timeout_seconds: float = DEFAULT_API_TIMEOUT_SECONDS,
        skip_archived: bool = True,
        strict: bool = False,
        client: Any | None = None,
    ) -> None:
        """Initialize an Amazon S3 SBOM prefix inventory backend.

        Args:
            bucket: Target S3 bucket name.
            prefix: Optional key prefix filter.
            suffixes: Filename suffixes selected as candidate SBOM objects.
            region_name: Optional AWS region.
            profile_name: Optional AWS shared profile.
            role_arn: Optional IAM role ARN assumed via STS ``AssumeRole``.
            external_id: Optional STS ``ExternalId`` paired with ``role_arn``.
            role_session_name: STS session identifier when assuming ``role_arn``.
            endpoint_url: Optional custom S3 / LocalStack / MinIO endpoint URL.
            allow_insecure_http: Permit ``http://`` custom endpoints for local testing only.
            expected_bucket_owner: Optional 12-digit AWS account ID verifying bucket ownership.
            max_objects: Maximum matching objects fetched before failing closed.
            max_pages: Maximum ``ListObjectsV2`` continuation pages.
            max_sbom_bytes: Maximum per-object byte limit (compressed and decompressed).
            max_concurrency: Bounded worker threads for S3 object downloads (``1..32``).
            max_retries: Bounded adaptive botocore retry attempts (``0..10``).
            timeout_seconds: Botocore request timeout in seconds.
            skip_archived: Skip ``GLACIER``/``DEEP_ARCHIVE`` objects cleanly when ``True``.
            strict: Raise :class:`BackendQueryError` if a matching object is not a valid SBOM.
            client: Optional pre-built boto3 S3 client (for testing).

        Raises:
            BackendConfigError: If bucket, prefix, suffixes, owner account, or bounds are invalid.
        """
        if not isinstance(strict, bool):
            raise BackendConfigError("Configuration option 'strict' must be a bool.")
        if not isinstance(skip_archived, bool):
            raise BackendConfigError("Configuration option 'skip_archived' must be a bool.")

        self._bucket = validate_s3_bucket(bucket)
        self._prefix = validate_s3_prefix(prefix)
        self._suffixes = tuple(
            validate_no_control_chars(s, field_name="suffixes", max_length=32).lower()
            for s in suffixes
        )
        self._region_name = validate_aws_region(region_name)
        self._profile_name = (
            validate_no_control_chars(profile_name, field_name="profile_name", max_length=128)
            if profile_name is not None
            else None
        )
        self._expected_bucket_owner = (
            validate_aws_account_id(expected_bucket_owner, field_name="expected_bucket_owner")
            if expected_bucket_owner is not None
            else None
        )
        self._max_objects = validate_bounded_int(
            max_objects, field_name="max_objects", min_value=1, max_value=10000
        )
        self._max_pages = validate_bounded_int(
            max_pages, field_name="max_pages", min_value=1, max_value=500
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
        self._timeout_seconds = validate_timeout_seconds(timeout_seconds)
        self._skip_archived = skip_archived
        self._strict = strict
        self._index: InMemoryComponentIndex | None = None

        if client is not None:
            self._client = client
            self._owns_client = False
        else:
            self._client = build_aws_client(
                "s3",
                region_name=self._region_name,
                profile_name=self._profile_name,
                role_arn=role_arn,
                external_id=external_id,
                role_session_name=role_session_name,
                endpoint_url=endpoint_url,
                allow_insecure_http=allow_insecure_http,
                timeout_seconds=self._timeout_seconds,
                max_retries=self._max_retries,
                max_pool_connections=max(10, self._max_concurrency + 2),
            )
            self._owns_client = True

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> S3SbomBackend:
        """Instantiate :class:`S3SbomBackend` from CLI options or YAML/JSON config."""
        reject_unknown_config_keys(config, _ALLOWED_CONFIG_KEYS, backend_name="s3_sbom")
        bucket = parse_optional_str_opt(config, "bucket", max_length=63)
        if bucket is None:
            raise BackendConfigError("S3SbomBackend requires 'bucket' configuration.")

        region = resolve_env_aws_region(
            parse_optional_str_opt(config, "region_name", max_length=64)
        )
        raw_suffixes = parse_str_list_opt(config, "suffixes", max_items=20, max_item_length=32)

        return cls(
            bucket=bucket,
            prefix=parse_optional_str_opt(config, "prefix", max_length=1024, allow_empty=True)
            or "",
            suffixes=raw_suffixes or DEFAULT_SBOM_SUFFIXES,
            region_name=region,
            profile_name=parse_optional_str_opt(config, "profile_name", max_length=128),
            role_arn=parse_optional_str_opt(config, "role_arn", max_length=512),
            external_id=parse_optional_str_opt(config, "external_id", max_length=1224),
            role_session_name=parse_optional_str_opt(config, "role_session_name", max_length=64)
            or "zerobom-s3-sbom",
            endpoint_url=parse_optional_str_opt(
                config, "endpoint_url", max_length=MAX_API_URL_LENGTH
            ),
            allow_insecure_http=parse_bool_opt(config, "allow_insecure_http", default=False),
            expected_bucket_owner=parse_optional_str_opt(
                config, "expected_bucket_owner", max_length=12
            ),
            max_objects=parse_int_opt(
                config, "max_objects", default=500, min_value=1, max_value=10000
            ),
            max_pages=parse_int_opt(config, "max_pages", default=50, min_value=1, max_value=500),
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
            timeout_seconds=parse_float_opt(
                config,
                "timeout_seconds",
                default=DEFAULT_API_TIMEOUT_SECONDS,
                min_value=0.5,
                max_value=120.0,
            ),
            skip_archived=parse_bool_opt(config, "skip_archived", default=True),
            strict=parse_bool_opt(config, "strict", default=False),
        )

    @property
    def name(self) -> str:
        """Registered backend plugin identifier (``"s3_sbom"``)."""
        return "s3_sbom"

    def close(self) -> None:
        """Close the internally managed boto3 S3 client."""
        if self._owns_client:
            close_fn = getattr(self._client, "close", None)
            if callable(close_fn):
                close_fn()

    def __repr__(self) -> str:
        """Return a safe representation of the S3 SBOM backend."""
        return (
            f"S3SbomBackend(bucket={self._bucket!r}, prefix={self._prefix!r}, "
            f"strict={self._strict}, skip_archived={self._skip_archived})"
        )

    def load(self) -> int:
        """List and index bounded CycloneDX/SPDX SBOM objects under the configured prefix."""
        self._index = load_s3_sbom_prefix(
            self._client,
            bucket=self._bucket,
            prefix=self._prefix,
            suffixes=self._suffixes,
            backend_name=self.name,
            max_objects=self._max_objects,
            max_pages=self._max_pages,
            max_sbom_bytes=self._max_sbom_bytes,
            strict=self._strict,
            skip_archived=self._skip_archived,
            expected_bucket_owner=self._expected_bucket_owner,
            max_concurrency=self._max_concurrency,
        )
        return len(self._index.components)

    def find_components(self, queries: Sequence[PackageQuery]) -> tuple[InventoryComponent, ...]:
        """Search indexed S3 CycloneDX/SPDX SBOM components for package matches."""
        if not queries:
            return ()
        if self._index is None:
            self.load()
        if self._index is None:
            return ()
        return self._index.find_components(queries)
