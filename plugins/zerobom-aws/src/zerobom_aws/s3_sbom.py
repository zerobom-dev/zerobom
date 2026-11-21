"""Amazon S3 CycloneDX & SPDX SBOM inventory backend plugin."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from typing import Any

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError

from zerobom.backends import (
    BackendConfigError,
    BackendQueryError,
    InMemoryComponentIndex,
    SbomParseError,
    parse_sbom_bytes,
)
from zerobom.backends._http import (
    DEFAULT_API_TIMEOUT_SECONDS,
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
from zerobom.backends.sbom_parser import MAX_SBOM_FILE_BYTES, clean_optional_str
from zerobom.models import InventoryComponent, PackageQuery

_S3_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_AWS_REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+$")
_DEFAULT_SUFFIXES: tuple[str, ...] = (".json", ".cdx.json", ".spdx.json")

_ALLOWED_CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "bucket",
        "prefix",
        "suffixes",
        "region_name",
        "profile_name",
        "max_objects",
        "max_pages",
        "max_sbom_bytes",
        "timeout_seconds",
        "strict",
    }
)


def _validate_s3_prefix(prefix: str) -> str:
    """Validate an S3 key prefix against control characters and traversal segments."""
    cleaned = validate_no_control_chars(
        prefix, field_name="prefix", max_length=1024, allow_empty=True
    )
    if "\\" in cleaned or any(seg == ".." for seg in cleaned.split("/")):
        raise BackendConfigError(
            f"S3 prefix {prefix!r} must not contain backslashes or '..' traversal segments."
        )
    return cleaned


class S3SbomBackend:
    """Amazon S3 CycloneDX & SPDX JSON SBOM prefix inventory backend."""

    def __init__(
        self,
        *,
        bucket: str,
        prefix: str = "",
        suffixes: Sequence[str] = _DEFAULT_SUFFIXES,
        region_name: str | None = None,
        profile_name: str | None = None,
        max_objects: int = 500,
        max_pages: int = 50,
        max_sbom_bytes: int = MAX_SBOM_FILE_BYTES,
        timeout_seconds: float = DEFAULT_API_TIMEOUT_SECONDS,
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
            max_objects: Maximum matching objects fetched before failing closed.
            max_pages: Maximum ``ListObjectsV2`` continuation pages.
            max_sbom_bytes: Maximum per-object byte limit prior to JSON parsing.
            timeout_seconds: Botocore request timeout in seconds.
            strict: Raise :class:`BackendQueryError` if a matching object is not a valid SBOM.
            client: Optional pre-built boto3 S3 client (for testing).

        Raises:
            BackendConfigError: If bucket, prefix, suffixes, or bounds are invalid.
        """
        if not isinstance(strict, bool):
            raise BackendConfigError("Configuration option 'strict' must be a bool.")

        cleaned_bucket = validate_no_control_chars(bucket, field_name="bucket", max_length=63)
        if ".." in cleaned_bucket or not _S3_BUCKET_RE.fullmatch(cleaned_bucket):
            raise BackendConfigError(f"Invalid S3 bucket name: {bucket!r}.")

        self._bucket = cleaned_bucket
        self._prefix = _validate_s3_prefix(prefix)
        self._suffixes = tuple(
            validate_no_control_chars(s, field_name="suffixes", max_length=32).lower()
            for s in suffixes
        )
        if region_name is not None:
            cleaned_region = validate_no_control_chars(
                region_name, field_name="region_name", max_length=64
            )
            if not _AWS_REGION_RE.fullmatch(cleaned_region):
                raise BackendConfigError(f"Invalid AWS region_name: {region_name!r}.")
            self._region_name: str | None = cleaned_region
        else:
            self._region_name = None
        self._profile_name = (
            validate_no_control_chars(profile_name, field_name="profile_name", max_length=128)
            if profile_name is not None
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
        self._timeout_seconds = validate_timeout_seconds(timeout_seconds)
        self._strict = strict
        self._index: InMemoryComponentIndex | None = None

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
            self._client = session.client("s3", config=boto_cfg)
            self._owns_client = True

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> S3SbomBackend:
        """Instantiate :class:`S3SbomBackend` from CLI options or YAML/JSON config."""
        reject_unknown_config_keys(config, _ALLOWED_CONFIG_KEYS, backend_name="s3_sbom")
        bucket = parse_optional_str_opt(config, "bucket", max_length=63)
        if bucket is None:
            raise BackendConfigError("S3SbomBackend requires 'bucket' configuration.")

        region = parse_optional_str_opt(config, "region_name", max_length=64)
        if region is None:
            raw_env_region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
            if raw_env_region and raw_env_region.strip():
                region = validate_no_control_chars(
                    raw_env_region, field_name="AWS_REGION", max_length=64
                )

        raw_suffixes = parse_str_list_opt(config, "suffixes", max_items=20, max_item_length=32)
        return cls(
            bucket=bucket,
            prefix=parse_optional_str_opt(config, "prefix", max_length=1024, allow_empty=True)
            or "",
            suffixes=raw_suffixes or _DEFAULT_SUFFIXES,
            region_name=region,
            profile_name=parse_optional_str_opt(config, "profile_name", max_length=128),
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
            timeout_seconds=parse_float_opt(
                config,
                "timeout_seconds",
                default=DEFAULT_API_TIMEOUT_SECONDS,
                min_value=0.5,
                max_value=120.0,
            ),
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
            f"strict={self._strict})"
        )

    def _matches_suffix(self, key: str) -> bool:
        """Return True if an S3 object key matches configured SBOM suffixes."""
        if not self._suffixes:
            return True
        lower = key.lower()
        return any(lower.endswith(suf) for suf in self._suffixes)

    def load(self) -> int:
        """List and index bounded CycloneDX/SPDX SBOM objects under the configured prefix."""
        entries: list[tuple[str, int | None, str | None]] = []
        continuation_token: str | None = None
        completed = False

        for _ in range(self._max_pages):
            kwargs: dict[str, Any] = {"Bucket": self._bucket, "Prefix": self._prefix}
            if continuation_token is not None:
                kwargs["ContinuationToken"] = continuation_token

            try:
                resp = self._client.list_objects_v2(**kwargs)
            except (ClientError, BotoCoreError) as exc:
                raise BackendQueryError(
                    f"[{self.name}] S3 ListObjectsV2 failed on "
                    f"s3://{self._bucket}/{self._prefix}: {exc}"
                ) from exc

            contents = resp.get("Contents")
            if isinstance(contents, list):
                for obj in contents:
                    if not isinstance(obj, Mapping):
                        continue
                    key = clean_optional_str(obj.get("Key"))
                    if key is None or not self._matches_suffix(key):
                        continue
                    if any(seg == ".." for seg in key.split("/")):
                        raise BackendQueryError(
                            f"[{self.name}] Disallowed traversal segment in S3 key {key!r}."
                        )
                    size = obj.get("Size")
                    etag = clean_optional_str(obj.get("ETag"))
                    entries.append((key, size if isinstance(size, int) else None, etag))
                    if len(entries) > self._max_objects:
                        raise BackendQueryError(
                            f"[{self.name}] Matching S3 SBOM objects exceeded "
                            f"max_objects={self._max_objects}."
                        )

            if not bool(resp.get("IsTruncated")):
                completed = True
                break
            continuation_token = clean_optional_str(resp.get("NextContinuationToken"))
            if continuation_token is None:
                completed = True
                break

        if not completed:
            raise BackendQueryError(
                f"[{self.name}] S3 ListObjectsV2 pagination exceeded max_pages={self._max_pages}."
            )

        index = InMemoryComponentIndex()
        for key, declared_size, etag in entries:
            if declared_size is not None and declared_size > self._max_sbom_bytes:
                raise BackendQueryError(
                    f"[{self.name}] S3 object s3://{self._bucket}/{key} declares size "
                    f"{declared_size} > limit {self._max_sbom_bytes} bytes."
                )

            raw_bytes = self._download_bounded_object(key)
            uri = f"s3://{self._bucket}/{key}"
            try:
                components = parse_sbom_bytes(
                    raw_bytes,
                    asset_id=uri,
                    backend=self.name,
                    location=uri,
                    scope=self._bucket,
                    extra_metadata={
                        "bucket": self._bucket,
                        "key": key,
                        "etag": etag,
                    },
                    max_bytes=self._max_sbom_bytes,
                )
            except SbomParseError as exc:
                if self._strict:
                    raise BackendQueryError(
                        f"[{self.name}] Failed to parse S3 SBOM {uri}: {exc}"
                    ) from exc
                continue
            index.add_components(components)

        self._index = index
        return len(index.components)

    def _download_bounded_object(self, key: str) -> bytes:
        """Download a single S3 object with strict ContentLength and read bounds."""
        try:
            resp = self._client.get_object(Bucket=self._bucket, Key=key)
        except (ClientError, BotoCoreError) as exc:
            raise BackendQueryError(
                f"[{self.name}] S3 GetObject failed for s3://{self._bucket}/{key}: {exc}"
            ) from exc

        content_length = resp.get("ContentLength")
        if isinstance(content_length, int) and content_length > self._max_sbom_bytes:
            body = resp.get("Body")
            if body is not None and callable(getattr(body, "close", None)):
                body.close()
            raise BackendQueryError(
                f"[{self.name}] S3 object s3://{self._bucket}/{key} ContentLength "
                f"({content_length} bytes) exceeds limit {self._max_sbom_bytes}."
            )

        body = resp.get("Body")
        if body is None or not callable(getattr(body, "read", None)):
            raise BackendQueryError(
                f"[{self.name}] S3 GetObject returned empty body stream for {key!r}."
            )
        try:
            raw = body.read(self._max_sbom_bytes + 1)
        except (OSError, BotoCoreError, ClientError) as exc:
            raise BackendQueryError(
                f"[{self.name}] Failed reading S3 body for {key!r}: {exc}"
            ) from exc
        finally:
            if callable(getattr(body, "close", None)):
                body.close()

        if not isinstance(raw, bytes) or len(raw) > self._max_sbom_bytes:
            raise BackendQueryError(
                f"[{self.name}] S3 object s3://{self._bucket}/{key} exceeds "
                f"limit {self._max_sbom_bytes} bytes."
            )
        return raw

    def find_components(self, queries: Sequence[PackageQuery]) -> tuple[InventoryComponent, ...]:
        """Search indexed S3 CycloneDX/SPDX SBOM components for package matches."""
        if not queries:
            return ()
        if self._index is None:
            self.load()
        if self._index is None:
            return ()
        return self._index.find_components(queries)
