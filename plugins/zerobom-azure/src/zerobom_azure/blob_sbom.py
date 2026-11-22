"""Azure Blob Storage CycloneDX & SPDX SBOM inventory backend plugin."""

from __future__ import annotations

import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote
from xml.parsers import expat

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
from zerobom_azure._auth import AzureTokenProvider, resolve_azure_cloud_preset
from zerobom_azure._common import (
    DEFAULT_SBOM_SUFFIXES,
    build_azure_http_client,
    maybe_decompress_sbom_bytes,
    request_with_retry,
)

_AZURE_ACCOUNT_RE = re.compile(r"^[a-z0-9]{3,24}$")
_AZURE_CONTAINER_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$")
_AZURE_STORAGE_API_VERSION = "2023-11-03"
_MAX_XML_LIST_BYTES = 10 * 1024 * 1024

_ALLOWED_CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "account_name",
        "container",
        "prefix",
        "suffixes",
        "cloud",
        "access_token",
        "sas_token",
        "use_default_credential",
        "endpoint_url",
        "max_objects",
        "max_pages",
        "max_sbom_bytes",
        "max_concurrency",
        "max_retries",
        "timeout_seconds",
        "ca_bundle",
        "verify_tls",
        "allow_insecure_http",
        "skip_archived",
        "strict",
    }
)


@dataclass(frozen=True)
class _BlobListEntry:
    """Internal parsed representation of one Azure Blob entry."""

    name: str
    content_length: int | None
    etag: str | None
    access_tier: str | None = None
    content_encoding: str | None = None


def _validate_prefix(prefix: str) -> str:
    """Validate Azure Blob prefix against control characters and traversal segments."""
    cleaned = validate_no_control_chars(
        prefix, field_name="prefix", max_length=1024, allow_empty=True
    )
    if "\\" in cleaned or any(seg == ".." for seg in cleaned.split("/")):
        raise BackendConfigError(
            f"Azure Blob prefix {prefix!r} must not contain backslashes or '..' segments."
        )
    return cleaned


def _parse_sas_token(raw_sas: str) -> tuple[tuple[str, str], ...]:
    """Parse an Azure SAS query string preserving literal ``+`` in base64 signatures."""
    cleaned = validate_no_control_chars(raw_sas, field_name="sas_token", max_length=4096).lstrip(
        "?"
    )
    pairs: list[tuple[str, str]] = []
    for part in cleaned.split("&"):
        if not part or "=" not in part:
            continue
        raw_k, raw_v = part.split("=", 1)
        key = unquote(raw_k).strip()
        val = unquote(raw_v)
        if key and val:
            pairs.append((key, val))
    if not pairs:
        raise BackendConfigError("Configuration option 'sas_token' must be non-empty.")
    return tuple(pairs)


def _has_c0_or_c1_control_chars(value: str) -> bool:
    """Return True if ``value`` contains C0 (``<32``) or DEL/C1 (``127..159``) chars."""
    return any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in value)


def _parse_blob_list_xml(
    raw_xml: bytes, *, context_url: str
) -> tuple[list[_BlobListEntry], str | None]:
    """Parse Azure Blob ListBlobs XML strictly using expat without DTD/entity support."""
    entries: list[_BlobListEntry] = []
    next_marker: str | None = None

    stack: list[str] = []
    text_buf: list[str] = []
    in_blob = False
    current_name: str | None = None
    current_length: int | None = None
    current_etag: str | None = None
    current_tier: str | None = None
    current_encoding: str | None = None

    def _forbid_dtd(*_args: Any, **_kwargs: Any) -> None:
        raise BackendQueryError(
            f"[azure_blob_sbom] DTD/DOCTYPE or ENTITY declaration forbidden "
            f"in XML from {context_url}."
        )

    def _on_start(tag_name: str, _attrs: dict[str, str]) -> None:
        nonlocal in_blob, current_name, current_length, current_etag
        nonlocal current_tier, current_encoding
        local_name = tag_name.rsplit("}", 1)[-1]
        stack.append(local_name)
        text_buf.clear()
        if local_name == "Blob":
            in_blob = True
            current_name = None
            current_length = None
            current_etag = None
            current_tier = None
            current_encoding = None

    def _on_char(data: str) -> None:
        text_buf.append(data)

    def _on_end(tag_name: str) -> None:
        nonlocal in_blob, current_name, current_length, current_etag
        nonlocal current_tier, current_encoding, next_marker
        local_name = tag_name.rsplit("}", 1)[-1]
        text = "".join(text_buf).strip()
        text_buf.clear()
        path = "/".join(stack)

        if in_blob:
            if path.endswith("Blob/Name") and text:
                current_name = text
            elif path.endswith("Blob/Properties/Content-Length") and text.isdigit():
                current_length = int(text)
            elif path.endswith("Blob/Properties/Etag") and text:
                current_etag = text
            elif path.endswith("Blob/Properties/AccessTier") and text:
                current_tier = text
            elif path.endswith("Blob/Properties/Content-Encoding") and text:
                current_encoding = text
            elif local_name == "Blob":
                if current_name is not None:
                    entries.append(
                        _BlobListEntry(
                            name=current_name,
                            content_length=current_length,
                            etag=current_etag,
                            access_tier=current_tier,
                            content_encoding=current_encoding,
                        )
                    )
                in_blob = False
        elif local_name == "NextMarker" and text:
            next_marker = text

        if stack:
            stack.pop()

    parser = expat.ParserCreate()
    parser.StartDoctypeDeclHandler = _forbid_dtd
    parser.EntityDeclHandler = _forbid_dtd
    parser.UnparsedEntityDeclHandler = _forbid_dtd
    parser.ExternalEntityRefHandler = lambda *_a: 0
    parser.StartElementHandler = _on_start
    parser.CharacterDataHandler = _on_char
    parser.EndElementHandler = _on_end

    try:
        parser.Parse(raw_xml, True)
    except BackendQueryError:
        raise
    except expat.ExpatError as exc:
        raise BackendQueryError(
            f"[azure_blob_sbom] Invalid Azure Blob XML listing from {context_url}: {exc}"
        ) from exc

    return entries, next_marker


class AzureBlobSbomBackend:
    """Azure Blob Storage CycloneDX & SPDX JSON SBOM prefix inventory backend."""

    def __init__(
        self,
        *,
        account_name: str,
        container: str,
        prefix: str = "",
        suffixes: Sequence[str] = DEFAULT_SBOM_SUFFIXES,
        cloud: str = "commercial",
        access_token: str | None = None,
        sas_token: str | None = None,
        use_default_credential: bool | None = None,
        endpoint_url: str | None = None,
        max_objects: int = 500,
        max_pages: int = 50,
        max_sbom_bytes: int = MAX_SBOM_FILE_BYTES,
        max_concurrency: int = 8,
        max_retries: int = 3,
        timeout_seconds: float = DEFAULT_API_TIMEOUT_SECONDS,
        ca_bundle: str | Path | None = None,
        verify_tls: bool = True,
        allow_insecure_http: bool = False,
        skip_archived: bool = True,
        strict: bool = False,
        http_client: httpx.Client | None = None,
        token_provider: AzureTokenProvider | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        """Initialize an Azure Blob Storage SBOM inventory backend.

        Raises:
            BackendConfigError: If storage account, container, auth, URL, TLS, or bounds fail.
        """
        if use_default_credential is not None and not isinstance(use_default_credential, bool):
            raise BackendConfigError(
                "Configuration option 'use_default_credential' must be a bool."
            )
        if not isinstance(verify_tls, bool):
            raise BackendConfigError("Configuration option 'verify_tls' must be a bool.")
        if not isinstance(allow_insecure_http, bool):
            raise BackendConfigError("Configuration option 'allow_insecure_http' must be a bool.")
        if not isinstance(skip_archived, bool):
            raise BackendConfigError("Configuration option 'skip_archived' must be a bool.")
        if not isinstance(strict, bool):
            raise BackendConfigError("Configuration option 'strict' must be a bool.")

        cleaned_account = validate_no_control_chars(
            account_name, field_name="account_name", max_length=24
        )
        if not _AZURE_ACCOUNT_RE.fullmatch(cleaned_account):
            raise BackendConfigError(f"Invalid Azure storage account name: {account_name!r}.")

        cleaned_container = validate_no_control_chars(
            container, field_name="container", max_length=63
        )
        if "--" in cleaned_container or not _AZURE_CONTAINER_RE.fullmatch(cleaned_container):
            raise BackendConfigError(f"Invalid Azure blob container name: {container!r}.")

        preset = resolve_azure_cloud_preset(cloud)
        self._cloud = preset.name
        self._account_name = cleaned_account
        self._container = cleaned_container
        self._prefix = _validate_prefix(prefix)
        self._suffixes = tuple(
            validate_no_control_chars(s, field_name="suffixes", max_length=32).lower()
            for s in suffixes
        )

        default_endpoint = f"https://{cleaned_account}.{preset.blob_endpoint_suffix}"
        self._endpoint_url = validate_api_base_url(
            endpoint_url or default_endpoint,
            allow_insecure_http=allow_insecure_http,
            field_name="endpoint_url",
        )

        self._sas_params: tuple[tuple[str, str], ...] = ()
        self._token_provider: AzureTokenProvider | None = None
        if sas_token is not None:
            if access_token is not None or use_default_credential is True:
                raise BackendConfigError(
                    "Specify either 'sas_token' or bearer/DefaultAzureCredential auth, not both."
                )
            self._sas_params = _parse_sas_token(sas_token)
        else:
            self._token_provider = token_provider or AzureTokenProvider(
                access_token=access_token,
                scope=preset.storage_scope,
                use_default_credential=use_default_credential,
                authority=preset.authority,
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
        self._sleep_fn = sleep_fn
        self._index: InMemoryComponentIndex | None = None

        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            verify_arg = resolve_tls_verify(verify_tls=verify_tls, ca_bundle=ca_bundle)
            self._client = build_azure_http_client(
                timeout_seconds=self._timeout_seconds,
                verify=verify_arg,
                max_concurrency=self._max_concurrency,
            )
            self._owns_client = True

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> AzureBlobSbomBackend:
        """Instantiate :class:`AzureBlobSbomBackend` from CLI or file config."""
        reject_unknown_config_keys(config, _ALLOWED_CONFIG_KEYS, backend_name="azure_blob_sbom")
        account_name = parse_optional_str_opt(config, "account_name", max_length=24)
        container = parse_optional_str_opt(config, "container", max_length=63)
        if account_name is None or container is None:
            raise BackendConfigError(
                "AzureBlobSbomBackend requires both 'account_name' and 'container'."
            )

        raw_use_dc = (
            parse_bool_opt(config, "use_default_credential", default=False)
            if "use_default_credential" in config and config["use_default_credential"] is not None
            else None
        )
        access_token = parse_optional_str_opt(config, "access_token", max_length=8192)
        sas_token: str | None = parse_optional_str_opt(config, "sas_token", max_length=4096)
        if (
            sas_token is None
            and access_token is None
            and raw_use_dc is not True
            and "sas_token" not in config
        ):
            raw_storage_env = os.environ.get("ZEROBOM_AZURE_SAS_TOKEN")
            if raw_storage_env and raw_storage_env.strip():
                sas_token = validate_no_control_chars(
                    raw_storage_env, field_name="ZEROBOM_AZURE_SAS_TOKEN", max_length=4096
                )

        raw_suffixes = parse_str_list_opt(config, "suffixes", max_items=20, max_item_length=32)
        return cls(
            account_name=account_name,
            container=container,
            prefix=parse_optional_str_opt(config, "prefix", max_length=1024, allow_empty=True)
            or "",
            suffixes=raw_suffixes or DEFAULT_SBOM_SUFFIXES,
            cloud=parse_optional_str_opt(config, "cloud", max_length=32) or "commercial",
            access_token=access_token,
            sas_token=sas_token,
            use_default_credential=raw_use_dc,
            endpoint_url=parse_optional_str_opt(
                config, "endpoint_url", max_length=MAX_API_URL_LENGTH
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
            ca_bundle=parse_optional_str_opt(config, "ca_bundle", max_length=2048),
            verify_tls=parse_bool_opt(config, "verify_tls", default=True),
            allow_insecure_http=parse_bool_opt(config, "allow_insecure_http", default=False),
            skip_archived=parse_bool_opt(config, "skip_archived", default=True),
            strict=parse_bool_opt(config, "strict", default=False),
        )

    @property
    def name(self) -> str:
        """Registered backend plugin identifier (``"azure_blob_sbom"``)."""
        return "azure_blob_sbom"

    def close(self) -> None:
        """Close the internally managed HTTP client session."""
        if self._owns_client:
            self._client.close()

    def __repr__(self) -> str:
        """Return a redacted summary that never exposes SAS signatures or bearer tokens."""
        auth_kind = "sas" if self._sas_params else "bearer"
        return (
            f"AzureBlobSbomBackend(account={self._account_name!r}, "
            f"container={self._container!r}, cloud={self._cloud!r}, auth={auth_kind!r}, "
            f"skip_archived={self._skip_archived}, strict={self._strict})"
        )

    def _matches_suffix(self, blob_name: str) -> bool:
        """Return True if the blob name matches configured SBOM suffixes."""
        if not self._suffixes:
            return True
        lower = blob_name.lower()
        return any(lower.endswith(suf) for suf in self._suffixes)

    def load(self) -> int:
        """List and index bounded CycloneDX/SPDX SBOM blobs under the container/prefix."""
        container_url = f"{self._endpoint_url}/{quote(self._container, safe='')}"
        base_headers = {"x-ms-version": _AZURE_STORAGE_API_VERSION}

        blobs: list[_BlobListEntry] = []
        marker: str | None = None
        completed = False

        for _ in range(self._max_pages):
            params: dict[str, str] = dict(self._sas_params)
            params.update(
                {
                    "restype": "container",
                    "comp": "list",
                    "maxresults": "200",
                }
            )
            if self._prefix:
                params["prefix"] = self._prefix
            if marker is not None:
                params["marker"] = marker

            status, _, raw_xml = request_with_retry(
                self._client,
                "GET",
                container_url,
                token_provider=self._token_provider,
                max_bytes=_MAX_XML_LIST_BYTES,
                backend_name=self.name,
                params=params,
                headers=base_headers,
                max_retries=self._max_retries,
                sleep_fn=self._sleep_fn,
            )
            self._check_status(status, container_url, body=raw_xml)
            page_blobs, marker = _parse_blob_list_xml(raw_xml, context_url=container_url)

            for entry in page_blobs:
                if _has_c0_or_c1_control_chars(entry.name):
                    raise BackendQueryError(
                        f"[{self.name}] Disallowed control char in Azure Blob name {entry.name!r}."
                    )
                if not self._matches_suffix(entry.name):
                    continue
                if any(seg == ".." for seg in entry.name.split("/")):
                    raise BackendQueryError(
                        f"[{self.name}] Disallowed traversal segment in Azure Blob {entry.name!r}."
                    )
                if entry.access_tier is not None and entry.access_tier.strip().lower() == "archive":
                    if self._skip_archived:
                        continue
                    raise BackendQueryError(
                        f"[{self.name}] Azure Blob {entry.name!r} resides in Archive access tier."
                    )
                blobs.append(entry)
                if len(blobs) > self._max_objects:
                    raise BackendQueryError(
                        f"[{self.name}] Matching Azure SBOM blobs exceeded "
                        f"max_objects={self._max_objects}."
                    )

            if marker is None:
                completed = True
                break

        if not completed:
            raise BackendQueryError(
                f"[{self.name}] Azure Blob listing exceeded max_pages={self._max_pages}."
            )

        for entry in blobs:
            if entry.content_length is not None and entry.content_length > self._max_sbom_bytes:
                raise BackendQueryError(
                    f"[{self.name}] Azure Blob {entry.name!r} declares Content-Length "
                    f"{entry.content_length} > limit {self._max_sbom_bytes} bytes."
                )

        def _process_blob(entry: _BlobListEntry) -> tuple[InventoryComponent, ...]:
            encoded_blob = "/".join(quote(seg, safe="") for seg in entry.name.split("/"))
            blob_url = f"{container_url}/{encoded_blob}"
            blob_params: dict[str, str] | None = (
                dict(self._sas_params) if self._sas_params else None
            )
            status, resp_headers, raw_bytes = request_with_retry(
                self._client,
                "GET",
                blob_url,
                token_provider=self._token_provider,
                max_bytes=self._max_sbom_bytes,
                backend_name=self.name,
                params=blob_params,
                headers=base_headers,
                max_retries=self._max_retries,
                sleep_fn=self._sleep_fn,
            )
            if status == 409 and self._skip_archived and b"BlobArchived" in raw_bytes:
                return ()
            self._check_status(status, blob_url, body=raw_bytes)

            uri = f"azblob://{self._account_name}/{self._container}/{entry.name}"
            effective_encoding = (
                clean_optional_str(resp_headers.get("content-encoding")) or entry.content_encoding
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
                    scope=f"{self._account_name}/{self._container}",
                    extra_metadata={
                        "account_name": self._account_name,
                        "container": self._container,
                        "blob": entry.name,
                        "etag": entry.etag,
                    },
                    max_bytes=self._max_sbom_bytes,
                )
            except SbomParseError as exc:
                if self._strict:
                    raise BackendQueryError(
                        f"[{self.name}] Failed to parse Azure Blob SBOM {uri}: {exc}"
                    ) from exc
                return ()

        index = InMemoryComponentIndex()
        if self._max_concurrency > 1 and len(blobs) > 1:
            ordered: list[tuple[InventoryComponent, ...] | None] = [None] * len(blobs)
            with ThreadPoolExecutor(max_workers=min(self._max_concurrency, len(blobs))) as pool:
                future_to_idx: dict[Future[tuple[InventoryComponent, ...]], int] = {
                    pool.submit(_process_blob, entry): idx for idx, entry in enumerate(blobs)
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
            for entry in blobs:
                comps = _process_blob(entry)
                if comps:
                    index.add_components(comps)

        self._index = index
        return len(index.components)

    def _check_status(self, status: int, url: str, *, body: bytes = b"") -> None:
        """Fail closed on redirects, auth failures, missing blobs, throttling, and errors."""
        if status in REDIRECT_STATUS_CODES:
            raise BackendQueryError(
                f"[{self.name}] Unexpected HTTP redirect ({status}) from {url}; redirects disabled."
            )
        if status in (401, 403):
            raise BackendQueryError(
                f"[{self.name}] Azure Blob authentication/SAS denied ({status}) at {url}."
            )
        if status == 404:
            raise BackendQueryError(
                f"[{self.name}] Azure Blob container or object not found (404) at {url}."
            )
        if status == 409 and b"BlobArchived" in body:
            raise BackendQueryError(
                f"[{self.name}] Azure Blob is in Archive tier (409 BlobArchived) at {url}."
            )
        if status == 429:
            raise BackendQueryError(f"[{self.name}] Azure Blob API throttled (429) at {url}.")
        if status != 200:
            raise BackendQueryError(
                f"[{self.name}] Azure Blob API returned unexpected status {status} at {url}."
            )

    def find_components(self, queries: Sequence[PackageQuery]) -> tuple[InventoryComponent, ...]:
        """Search indexed Azure Blob CycloneDX/SPDX SBOM components for package matches."""
        if not queries:
            return ()
        if self._index is None:
            self.load()
        if self._index is None:
            return ()
        return self._index.find_components(queries)
