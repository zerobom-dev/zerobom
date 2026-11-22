"""Shared Azure HTTP client, quota/retry helper, gzip decompression, and JSON decoder."""

from __future__ import annotations

import json
import random
import re
import ssl
import time
import zlib
from collections.abc import Callable, Mapping
from typing import Any

import httpx

from zerobom._version import DEFAULT_USER_AGENT
from zerobom.backends import BackendQueryError, SbomParseError
from zerobom.backends._http import read_bounded_response
from zerobom_azure._auth import AzureTokenProvider

DEFAULT_SBOM_SUFFIXES: tuple[str, ...] = (
    ".json",
    ".cdx.json",
    ".spdx.json",
    ".json.gz",
    ".cdx.json.gz",
    ".spdx.json.gz",
)
_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503, 504})
_MAX_BACKOFF_SECONDS = 30.0
_DECOMPRESS_CHUNK_BYTES = 65536
_TIMESPAN_RE = re.compile(r"^(?:(\d+)\.)?(\d{1,2}):(\d{2}):(\d{2}(?:\.\d+)?)$")


def build_azure_http_client(
    *,
    timeout_seconds: float,
    verify: bool | ssl.SSLContext,
    max_concurrency: int = 8,
) -> httpx.Client:
    """Construct a hardened ``httpx.Client`` for Azure REST APIs."""
    pool_size = max(10, max_concurrency)
    return httpx.Client(
        timeout=timeout_seconds,
        verify=verify,
        follow_redirects=False,
        trust_env=False,
        headers={"User-Agent": f"zerobom-azure/0.1.0 ({DEFAULT_USER_AGENT})"},
        limits=httpx.Limits(max_connections=pool_size * 2, max_keepalive_connections=pool_size),
    )


def parse_azure_timespan_seconds(raw: str | None) -> float | None:
    """Parse Azure ``x-ms-user-quota-resets-after`` (``HH:MM:SS``) or ``Retry-After`` seconds."""
    if raw is None:
        return None
    cleaned = raw.strip()
    if not cleaned:
        return None
    try:
        secs = float(cleaned)
        if secs >= 0:
            return min(secs, _MAX_BACKOFF_SECONDS)
    except ValueError:
        pass

    if match := _TIMESPAN_RE.fullmatch(cleaned):
        days = int(match.group(1) or 0)
        hours = int(match.group(2))
        minutes = int(match.group(3))
        seconds = float(match.group(4))
        total = ((days * 24 + hours) * 60 + minutes) * 60 + seconds
        return max(0.0, min(total, _MAX_BACKOFF_SECONDS))

    return None


def _is_transient_transport_error(exc: BackendQueryError) -> bool:
    """Return True if ``exc`` wraps a transient network or timeout error."""
    cause = exc.__cause__
    return isinstance(
        cause, (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError)
    )


def request_with_retry(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    token_provider: AzureTokenProvider | None,
    max_bytes: int,
    backend_name: str,
    params: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    json_body: Any | None = None,
    max_retries: int = 3,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> tuple[int, httpx.Headers, bytes]:
    """Execute a bounded Azure HTTP request with 401 refresh and quota-aware 429/5xx backoff."""
    auth_refreshed = False

    for attempt in range(max_retries + 1):
        req_headers = dict(headers) if headers else {}
        if token_provider is not None:
            force = auth_refreshed and attempt == 0
            req_headers["Authorization"] = f"Bearer {token_provider.get_token(force_refresh=force)}"

        try:
            status, resp_headers, body = read_bounded_response(
                client,
                method,
                url,
                max_bytes=max_bytes,
                params=params,
                headers=req_headers,
                json_body=json_body,
                backend_name=backend_name,
            )
        except BackendQueryError as exc:
            if attempt < max_retries and _is_transient_transport_error(exc):
                delay = min(0.5 * (2**attempt) + random.uniform(0.0, 0.25), _MAX_BACKOFF_SECONDS)  # noqa: S311
                sleep_fn(delay)
                continue
            raise

        if (
            status == 401
            and token_provider is not None
            and token_provider.can_refresh
            and not auth_refreshed
        ):
            refreshed = token_provider.get_token(force_refresh=True)
            auth_refreshed = True
            req_headers["Authorization"] = f"Bearer {refreshed}"
            status, resp_headers, body = read_bounded_response(
                client,
                method,
                url,
                max_bytes=max_bytes,
                params=params,
                headers=req_headers,
                json_body=json_body,
                backend_name=backend_name,
            )

        if status in _RETRYABLE_STATUS_CODES and attempt < max_retries:
            quota_delay = parse_azure_timespan_seconds(
                resp_headers.get("retry-after") or resp_headers.get("x-ms-user-quota-resets-after")
            )
            delay = (
                quota_delay
                if quota_delay is not None
                else min(0.5 * (2**attempt) + random.uniform(0.0, 0.25), _MAX_BACKOFF_SECONDS)  # noqa: S311
            )
            sleep_fn(delay)
            continue

        return status, resp_headers, body

    raise BackendQueryError(f"[{backend_name}] Exhausted retries requesting Azure endpoint {url}.")


def maybe_decompress_sbom_bytes(
    raw: bytes,
    *,
    object_label: str,
    content_encoding: str | None,
    max_bytes: int,
    backend_name: str,
) -> bytes:
    """Stream-decompress gzip Azure Blob SBOM bytes while strictly enforcing ``max_bytes``."""
    has_gzip_magic = raw[:2] == b"\x1f\x8b"
    expects_gzip = object_label.lower().endswith(".gz") or (
        content_encoding is not None and "gzip" in content_encoding.lower()
    )
    already_plain_json = not has_gzip_magic and raw.lstrip()[:1] in (b"{", b"[")
    if not has_gzip_magic and (not expects_gzip or already_plain_json):
        if len(raw) > max_bytes:
            raise BackendQueryError(
                f"[{backend_name}] Azure Blob {object_label} exceeds limit {max_bytes} bytes."
            )
        return raw

    decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = bytearray()
    try:
        for offset in range(0, len(raw), _DECOMPRESS_CHUNK_BYTES):
            chunk = raw[offset : offset + _DECOMPRESS_CHUNK_BYTES]
            remaining = max_bytes - len(out)
            piece = decomp.decompress(chunk, max_length=remaining + 1)
            out.extend(piece)
            if len(out) > max_bytes or decomp.unconsumed_tail:
                raise BackendQueryError(
                    f"[{backend_name}] Decompressed SBOM {object_label} exceeds "
                    f"limit {max_bytes} bytes."
                )
        if not decomp.eof:
            raise SbomParseError(f"Truncated gzip stream in SBOM {object_label}.")
        tail = decomp.flush(max_bytes - len(out) + 1)
        out.extend(tail)
    except BackendQueryError:
        raise
    except zlib.error as exc:
        raise SbomParseError(f"Corrupt gzip SBOM stream in {object_label}: {exc}") from exc

    if len(out) > max_bytes:
        raise BackendQueryError(
            f"[{backend_name}] Decompressed SBOM {object_label} exceeds limit {max_bytes} bytes."
        )
    return bytes(out)


def decode_json_dict(body: bytes, url: str, backend_name: str) -> dict[str, Any]:
    """Decode UTF-8 JSON object from an Azure REST response guarding against deep nesting."""
    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BackendQueryError(
            f"[{backend_name}] Invalid JSON response from {url}: {exc}"
        ) from exc
    if not isinstance(decoded, dict):
        raise BackendQueryError(f"[{backend_name}] Expected JSON object from {url}.")
    return decoded
