"""Google Cloud Storage CycloneDX & SPDX SBOM inventory backend plugin."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from zerobom.backends import (
    BackendConfigError,
    BackendQueryError,
    InMemoryComponentIndex,
    SbomParseError,
    parse_sbom_bytes,
)
from zerobom.backends._http import (
    DEFAULT_API_TIMEOUT_SECONDS,
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
from zerobom.backends.sbom_parser import MAX_SBOM_FILE_BYTES, clean_optional_str
from zerobom.models import InventoryComponent, PackageQuery
from zerobom_gcp._auth import resolve_gcp_bearer_token

DEFAULT_GCS_API_URL = "https://storage.googleapis.com"
DEFAULT_API_LIST_BYTES = 10 * 1024 * 1024
_GCS_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$")
_DEFAULT_SUFFIXES: tuple[str, ...] = (".json", ".cdx.json", ".spdx.json")

_ALLOWED_CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "bucket",
        "prefix",
        "suffixes",
        "access_token",
        "use_adc",
        "api_base_url",
        "max_objects",
        "max_pages",
        "max_sbom_bytes",
        "timeout_seconds",
        "ca_bundle",
        "verify_tls",
        "allow_insecure_http",
        "strict",
    }
)


def _validate_prefix(prefix: str) -> str:
    """Validate GCS object prefix against control characters and traversal segments."""
    cleaned = validate_no_control_chars(
        prefix, field_name="prefix", max_length=1024, allow_empty=True
    )
    if "\\" in cleaned or any(seg == ".." for seg in cleaned.split("/")):
        raise BackendConfigError(
            f"GCS prefix {prefix!r} must not contain backslashes or '..' traversal segments."
        )
    return cleaned


class GcsSbomBackend:
    """Google Cloud Storage CycloneDX & SPDX JSON SBOM prefix inventory backend."""

    def __init__(
        self,
        *,
        bucket: str,
        prefix: str = "",
        suffixes: Sequence[str] = _DEFAULT_SUFFIXES,
        access_token: str | None = None,
        use_adc: bool = False,
        api_base_url: str = DEFAULT_GCS_API_URL,
        max_objects: int = 500,
        max_pages: int = 50,
        max_sbom_bytes: int = MAX_SBOM_FILE_BYTES,
        timeout_seconds: float = DEFAULT_API_TIMEOUT_SECONDS,
        ca_bundle: str | Path | None = None,
        verify_tls: bool = True,
        allow_insecure_http: bool = False,
        strict: bool = False,
        http_client: httpx.Client | None = None,
    ) -> None:
        """Initialize a Google Cloud Storage JSON API v1 SBOM inventory backend.

        Raises:
            BackendConfigError: If bucket, prefix, auth, URL, TLS, or bounds are invalid.
        """
        if not isinstance(use_adc, bool):
            raise BackendConfigError("Configuration option 'use_adc' must be a bool.")
        if not isinstance(verify_tls, bool):
            raise BackendConfigError("Configuration option 'verify_tls' must be a bool.")
        if not isinstance(allow_insecure_http, bool):
            raise BackendConfigError("Configuration option 'allow_insecure_http' must be a bool.")
        if not isinstance(strict, bool):
            raise BackendConfigError("Configuration option 'strict' must be a bool.")

        cleaned_bucket = validate_no_control_chars(bucket, field_name="bucket", max_length=222)
        if ".." in cleaned_bucket or not _GCS_BUCKET_RE.fullmatch(cleaned_bucket):
            raise BackendConfigError(f"Invalid GCS bucket name: {bucket!r}.")

        self._bucket = cleaned_bucket
        self._prefix = _validate_prefix(prefix)
        self._suffixes = tuple(
            validate_no_control_chars(s, field_name="suffixes", max_length=32).lower()
            for s in suffixes
        )
        self._api_base_url = validate_api_base_url(
            api_base_url,
            allow_insecure_http=allow_insecure_http,
            field_name="api_base_url",
        )
        self._bearer_token = resolve_gcp_bearer_token(access_token, use_adc=use_adc)
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
    def from_config(cls, config: Mapping[str, Any]) -> GcsSbomBackend:
        """Instantiate :class:`GcsSbomBackend` from CLI options or YAML/JSON config."""
        reject_unknown_config_keys(config, _ALLOWED_CONFIG_KEYS, backend_name="gcs_sbom")
        bucket = parse_optional_str_opt(config, "bucket", max_length=222)
        if bucket is None:
            raise BackendConfigError("GcsSbomBackend requires 'bucket' configuration.")

        raw_suffixes = parse_str_list_opt(config, "suffixes", max_items=20, max_item_length=32)
        return cls(
            bucket=bucket,
            prefix=parse_optional_str_opt(config, "prefix", max_length=1024, allow_empty=True)
            or "",
            suffixes=raw_suffixes or _DEFAULT_SUFFIXES,
            access_token=parse_optional_str_opt(config, "access_token", max_length=8192),
            use_adc=parse_bool_opt(config, "use_adc", default=False),
            api_base_url=parse_optional_str_opt(
                config, "api_base_url", max_length=MAX_API_URL_LENGTH
            )
            or DEFAULT_GCS_API_URL,
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
            ca_bundle=parse_optional_str_opt(config, "ca_bundle", max_length=2048),
            verify_tls=parse_bool_opt(config, "verify_tls", default=True),
            allow_insecure_http=parse_bool_opt(config, "allow_insecure_http", default=False),
            strict=parse_bool_opt(config, "strict", default=False),
        )

    @property
    def name(self) -> str:
        """Registered backend plugin identifier (``"gcs_sbom"``)."""
        return "gcs_sbom"

    def close(self) -> None:
        """Close the internally managed HTTP client session."""
        if self._owns_client:
            self._client.close()

    def __repr__(self) -> str:
        """Return a redacted summary without leaking GCP bearer credentials."""
        return (
            f"GcsSbomBackend(bucket={self._bucket!r}, prefix={self._prefix!r}, "
            f"strict={self._strict})"
        )

    def _matches_suffix(self, obj_name: str) -> bool:
        """Return True if the object name matches configured SBOM suffixes."""
        if not self._suffixes:
            return True
        lower = obj_name.lower()
        return any(lower.endswith(suf) for suf in self._suffixes)

    def load(self) -> int:
        """List and index bounded CycloneDX/SPDX SBOM objects under the configured GCS prefix."""
        list_url = f"{self._api_base_url}/storage/v1/b/{quote(self._bucket, safe='')}/o"
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._bearer_token}",
        }

        objects: list[tuple[str, int | None, str | None]] = []
        page_token: str | None = None
        completed = False

        for _ in range(self._max_pages):
            params: dict[str, str] = {"maxResults": "200"}
            if self._prefix:
                params["prefix"] = self._prefix
            if page_token is not None:
                params["pageToken"] = page_token

            status, _, body = read_bounded_response(
                self._client,
                "GET",
                list_url,
                max_bytes=DEFAULT_API_LIST_BYTES,
                params=params,
                headers=headers,
                backend_name=self.name,
            )
            self._check_status(status, list_url)
            doc = self._decode_json_dict(body, list_url)

            raw_items = doc.get("items")
            if isinstance(raw_items, list):
                for item in raw_items:
                    if not isinstance(item, Mapping):
                        continue
                    obj_name = clean_optional_str(item.get("name"))
                    if obj_name is None or not self._matches_suffix(obj_name):
                        continue
                    if any(seg == ".." for seg in obj_name.split("/")):
                        raise BackendQueryError(
                            f"[{self.name}] Disallowed traversal segment in GCS object "
                            f"{obj_name!r}."
                        )
                    raw_size = item.get("size")
                    size_int = (
                        int(raw_size)
                        if isinstance(raw_size, str) and raw_size.isdigit()
                        else raw_size
                        if isinstance(raw_size, int) and not isinstance(raw_size, bool)
                        else None
                    )
                    etag = clean_optional_str(item.get("etag"))
                    objects.append((obj_name, size_int, etag))
                    if len(objects) > self._max_objects:
                        raise BackendQueryError(
                            f"[{self.name}] Matching GCS SBOM objects exceeded "
                            f"max_objects={self._max_objects}."
                        )

            page_token = clean_optional_str(doc.get("nextPageToken"))
            if page_token is None:
                completed = True
                break

        if not completed:
            raise BackendQueryError(
                f"[{self.name}] GCS object listing exceeded max_pages={self._max_pages}."
            )

        index = InMemoryComponentIndex()
        for obj_name, declared_size, etag in objects:
            if declared_size is not None and declared_size > self._max_sbom_bytes:
                raise BackendQueryError(
                    f"[{self.name}] GCS object gs://{self._bucket}/{obj_name} declares size "
                    f"{declared_size} > limit {self._max_sbom_bytes} bytes."
                )

            obj_url = (
                f"{self._api_base_url}/storage/v1/b/{quote(self._bucket, safe='')}/o/"
                f"{quote(obj_name, safe='')}"
            )
            status, _, raw_bytes = read_bounded_response(
                self._client,
                "GET",
                obj_url,
                max_bytes=self._max_sbom_bytes,
                params={"alt": "media"},
                headers={"Authorization": f"Bearer {self._bearer_token}"},
                backend_name=self.name,
            )
            self._check_status(status, obj_url)

            uri = f"gs://{self._bucket}/{obj_name}"
            try:
                components = parse_sbom_bytes(
                    raw_bytes,
                    asset_id=uri,
                    backend=self.name,
                    location=uri,
                    scope=self._bucket,
                    extra_metadata={"bucket": self._bucket, "object": obj_name, "etag": etag},
                    max_bytes=self._max_sbom_bytes,
                )
            except SbomParseError as exc:
                if self._strict:
                    raise BackendQueryError(
                        f"[{self.name}] Failed to parse GCS SBOM {uri}: {exc}"
                    ) from exc
                continue
            index.add_components(components)

        self._index = index
        return len(index.components)

    def _check_status(self, status: int, url: str) -> None:
        """Fail closed on redirects, auth failures, missing buckets, rate limits, and errors."""
        if status in REDIRECT_STATUS_CODES:
            raise BackendQueryError(
                f"[{self.name}] Unexpected HTTP redirect ({status}) from {url}; redirects disabled."
            )
        if status in (401, 403):
            raise BackendQueryError(
                f"[{self.name}] GCS authentication/authorization denied ({status}) at {url}."
            )
        if status == 404:
            raise BackendQueryError(f"[{self.name}] GCS bucket or object not found (404) at {url}.")
        if status == 429:
            raise BackendQueryError(f"[{self.name}] GCS API rate limited (429) at {url}.")
        if status != 200:
            raise BackendQueryError(
                f"[{self.name}] GCS API returned unexpected status {status} at {url}."
            )

    def _decode_json_dict(self, body: bytes, url: str) -> dict[str, Any]:
        """Decode UTF-8 JSON object from GCS JSON API."""
        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BackendQueryError(
                f"[{self.name}] Invalid JSON response from {url}: {exc}"
            ) from exc
        if not isinstance(decoded, dict):
            raise BackendQueryError(f"[{self.name}] Expected JSON object from {url}.")
        return decoded

    def find_components(self, queries: Sequence[PackageQuery]) -> tuple[InventoryComponent, ...]:
        """Search indexed GCS CycloneDX/SPDX SBOM components for package matches."""
        if not queries:
            return ()
        if self._index is None:
            self.load()
        if self._index is None:
            return ()
        return self._index.find_components(queries)
