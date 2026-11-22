"""Google Cloud Storage CycloneDX & SPDX SBOM inventory backend plugin."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
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
    reject_unknown_config_keys,
    resolve_tls_verify,
    validate_api_base_url,
    validate_bounded_int,
    validate_no_control_chars,
    validate_timeout_seconds,
)
from zerobom.backends.sbom_parser import MAX_SBOM_FILE_BYTES, clean_optional_str
from zerobom.models import InventoryComponent, PackageQuery
from zerobom_gcp._auth import GcpTokenProvider
from zerobom_gcp._common import (
    DEFAULT_SBOM_SUFFIXES,
    build_gcp_http_client,
    decode_json_dict,
    maybe_decompress_sbom_bytes,
    request_with_retry,
    validate_gcs_bucket,
)

DEFAULT_GCS_API_URL = "https://storage.googleapis.com"
DEFAULT_API_LIST_BYTES = 10 * 1024 * 1024

_ALLOWED_CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "bucket",
        "prefix",
        "suffixes",
        "access_token",
        "use_adc",
        "user_project",
        "api_base_url",
        "max_objects",
        "max_pages",
        "max_sbom_bytes",
        "max_concurrency",
        "max_retries",
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
        suffixes: Sequence[str] = DEFAULT_SBOM_SUFFIXES,
        access_token: str | None = None,
        use_adc: bool | None = None,
        user_project: str | None = None,
        api_base_url: str = DEFAULT_GCS_API_URL,
        max_objects: int = 500,
        max_pages: int = 50,
        max_sbom_bytes: int = MAX_SBOM_FILE_BYTES,
        max_concurrency: int = 8,
        max_retries: int = 3,
        timeout_seconds: float = DEFAULT_API_TIMEOUT_SECONDS,
        ca_bundle: str | Path | None = None,
        verify_tls: bool = True,
        allow_insecure_http: bool = False,
        strict: bool = False,
        http_client: httpx.Client | None = None,
        token_provider: GcpTokenProvider | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        """Initialize a Google Cloud Storage JSON API v1 SBOM inventory backend.

        Raises:
            BackendConfigError: If bucket, prefix, auth, URL, TLS, or bounds are invalid.
        """
        if use_adc is not None and not isinstance(use_adc, bool):
            raise BackendConfigError("Configuration option 'use_adc' must be a bool.")
        if not isinstance(verify_tls, bool):
            raise BackendConfigError("Configuration option 'verify_tls' must be a bool.")
        if not isinstance(allow_insecure_http, bool):
            raise BackendConfigError("Configuration option 'allow_insecure_http' must be a bool.")
        if not isinstance(strict, bool):
            raise BackendConfigError("Configuration option 'strict' must be a bool.")

        self._bucket = validate_gcs_bucket(bucket)
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
        self._token_provider = token_provider or GcpTokenProvider(
            access_token=access_token, use_adc=use_adc
        )
        self._user_project = (
            validate_no_control_chars(user_project, field_name="user_project", max_length=64)
            if user_project is not None
            else self._token_provider.quota_project_id
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
        self._strict = strict
        self._sleep_fn = sleep_fn
        self._index: InMemoryComponentIndex | None = None

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
    def from_config(cls, config: Mapping[str, Any]) -> GcsSbomBackend:
        """Instantiate :class:`GcsSbomBackend` from CLI options or YAML/JSON config."""
        reject_unknown_config_keys(config, _ALLOWED_CONFIG_KEYS, backend_name="gcs_sbom")
        bucket = parse_optional_str_opt(config, "bucket", max_length=222)
        if bucket is None:
            raise BackendConfigError("GcsSbomBackend requires 'bucket' configuration.")

        raw_use_adc = (
            parse_bool_opt(config, "use_adc", default=False)
            if "use_adc" in config and config["use_adc"] is not None
            else None
        )
        raw_suffixes = parse_str_list_opt(config, "suffixes", max_items=20, max_item_length=32)

        return cls(
            bucket=bucket,
            prefix=parse_optional_str_opt(config, "prefix", max_length=1024, allow_empty=True)
            or "",
            suffixes=raw_suffixes or DEFAULT_SBOM_SUFFIXES,
            access_token=parse_optional_str_opt(config, "access_token", max_length=8192),
            use_adc=raw_use_adc,
            user_project=parse_optional_str_opt(config, "user_project", max_length=64),
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
        list_headers = {"Accept": "application/json"}

        objects: list[tuple[str, int | None, str | None, str | None]] = []
        page_token: str | None = None
        completed = False

        for _ in range(self._max_pages):
            params: dict[str, str] = {"maxResults": "200"}
            if self._prefix:
                params["prefix"] = self._prefix
            if self._user_project is not None:
                params["userProject"] = self._user_project
            if page_token is not None:
                params["pageToken"] = page_token

            status, _, body = request_with_retry(
                self._client,
                "GET",
                list_url,
                token_provider=self._token_provider,
                max_bytes=DEFAULT_API_LIST_BYTES,
                backend_name=self.name,
                params=params,
                headers=list_headers,
                max_retries=self._max_retries,
                sleep_fn=self._sleep_fn,
            )
            self._check_status(status, list_url)
            doc = decode_json_dict(body, list_url, self.name)

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
                    content_encoding = clean_optional_str(item.get("contentEncoding"))
                    objects.append((obj_name, size_int, etag, content_encoding))
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

        for obj_name, declared_size, _, _ in objects:
            if declared_size is not None and declared_size > self._max_sbom_bytes:
                raise BackendQueryError(
                    f"[{self.name}] GCS object gs://{self._bucket}/{obj_name} declares size "
                    f"{declared_size} > limit {self._max_sbom_bytes} bytes."
                )

        def _process_object(
            item: tuple[str, int | None, str | None, str | None],
        ) -> tuple[InventoryComponent, ...]:
            obj_name, _, etag, listed_encoding = item
            obj_url = (
                f"{self._api_base_url}/storage/v1/b/{quote(self._bucket, safe='')}/o/"
                f"{quote(obj_name, safe='')}"
            )
            dl_params: dict[str, str] = {"alt": "media"}
            if self._user_project is not None:
                dl_params["userProject"] = self._user_project

            status, resp_headers, raw_bytes = request_with_retry(
                self._client,
                "GET",
                obj_url,
                token_provider=self._token_provider,
                max_bytes=self._max_sbom_bytes,
                backend_name=self.name,
                params=dl_params,
                max_retries=self._max_retries,
                sleep_fn=self._sleep_fn,
            )
            self._check_status(status, obj_url)

            uri = f"gs://{self._bucket}/{obj_name}"
            effective_encoding = (
                clean_optional_str(resp_headers.get("content-encoding")) or listed_encoding
            )
            try:
                plain_bytes = maybe_decompress_sbom_bytes(
                    raw_bytes,
                    object_label=uri,
                    content_encoding=effective_encoding,
                    max_bytes=self._max_sbom_bytes,
                    backend_name=self.name,
                )
                return parse_sbom_bytes(
                    plain_bytes,
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
                return ()

        index = InMemoryComponentIndex()
        if self._max_concurrency > 1 and len(objects) > 1:
            ordered: list[tuple[InventoryComponent, ...] | None] = [None] * len(objects)
            with ThreadPoolExecutor(max_workers=min(self._max_concurrency, len(objects))) as pool:
                future_to_idx: dict[Future[tuple[InventoryComponent, ...]], int] = {
                    pool.submit(_process_object, item): idx for idx, item in enumerate(objects)
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
            for item in objects:
                comps = _process_object(item)
                if comps:
                    index.add_components(comps)

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

    def find_components(self, queries: Sequence[PackageQuery]) -> tuple[InventoryComponent, ...]:
        """Search indexed GCS CycloneDX/SPDX SBOM components for package matches."""
        if not queries:
            return ()
        if self._index is None:
            self.load()
        if self._index is None:
            return ()
        return self._index.find_components(queries)
