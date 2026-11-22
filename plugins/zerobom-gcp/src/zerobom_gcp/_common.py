"""Shared GCP HTTP client, quota/retry helper, gzip decompression, and URI validation."""

from __future__ import annotations

import json
import random
import re
import ssl
import time
import zlib
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from zerobom._version import DEFAULT_USER_AGENT
from zerobom.backends import BackendConfigError, BackendQueryError, SbomParseError
from zerobom.backends._http import read_bounded_response, validate_no_control_chars
from zerobom_gcp._auth import GcpTokenProvider

GCS_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$")
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


def build_gcp_http_client(
    *,
    timeout_seconds: float,
    verify: bool | ssl.SSLContext,
    max_concurrency: int = 8,
) -> httpx.Client:
    """Construct a hardened ``httpx.Client`` for GCP REST APIs."""
    pool_size = max(10, max_concurrency)
    return httpx.Client(
        timeout=timeout_seconds,
        verify=verify,
        follow_redirects=False,
        trust_env=False,
        headers={"User-Agent": f"zerobom-gcp/0.1.0 ({DEFAULT_USER_AGENT})"},
        limits=httpx.Limits(max_connections=pool_size * 2, max_keepalive_connections=pool_size),
    )


def parse_retry_after_seconds(raw: str | None) -> float | None:
    """Parse an HTTP ``Retry-After`` header (seconds or HTTP-date), capped at 30 seconds."""
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
    try:
        dt = parsedate_to_datetime(cleaned)
        dt_utc = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
        delta = (dt_utc - datetime.now(UTC)).total_seconds()
        return max(0.0, min(delta, _MAX_BACKOFF_SECONDS))
    except (TypeError, ValueError):
        return None


def _is_transient_transport_error(exc: BackendQueryError) -> bool:
    """Return True if a wrapped ``BackendQueryError`` came from a transient network error."""
    cause = exc.__cause__
    return isinstance(
        cause, (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError)
    )


def request_with_retry(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    token_provider: GcpTokenProvider,
    max_bytes: int,
    backend_name: str,
    params: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    max_retries: int = 3,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> tuple[int, httpx.Headers, bytes]:
    """Execute a bounded GCP HTTP request with 401 refresh and 429/5xx backoff."""
    auth_refreshed = False

    for attempt in range(max_retries + 1):
        force = auth_refreshed and attempt == 0
        token = token_provider.get_token(force_refresh=force)
        req_headers = dict(headers) if headers else {}
        req_headers["Authorization"] = f"Bearer {token}"

        try:
            status, resp_headers, body = read_bounded_response(
                client,
                method,
                url,
                max_bytes=max_bytes,
                params=params,
                headers=req_headers,
                backend_name=backend_name,
            )
        except BackendQueryError as exc:
            if attempt < max_retries and _is_transient_transport_error(exc):
                delay = min(0.5 * (2**attempt) + random.uniform(0.0, 0.25), _MAX_BACKOFF_SECONDS)  # noqa: S311
                sleep_fn(delay)
                continue
            raise

        if status == 401 and token_provider.can_refresh and not auth_refreshed:
            token_provider.get_token(force_refresh=True)
            auth_refreshed = True
            token = token_provider.get_token()
            req_headers["Authorization"] = f"Bearer {token}"
            status, resp_headers, body = read_bounded_response(
                client,
                method,
                url,
                max_bytes=max_bytes,
                params=params,
                headers=req_headers,
                backend_name=backend_name,
            )

        if status in _RETRYABLE_STATUS_CODES and attempt < max_retries:
            retry_after = parse_retry_after_seconds(resp_headers.get("retry-after"))
            delay = (
                retry_after
                if retry_after is not None
                else min(0.5 * (2**attempt) + random.uniform(0.0, 0.25), _MAX_BACKOFF_SECONDS)  # noqa: S311
            )
            sleep_fn(delay)
            continue

        return status, resp_headers, body

    raise BackendQueryError(f"[{backend_name}] Exhausted retries requesting GCP endpoint {url}.")


def maybe_decompress_sbom_bytes(
    raw: bytes,
    *,
    object_label: str,
    content_encoding: str | None,
    max_bytes: int,
    backend_name: str,
) -> bytes:
    """Stream-decompress gzip GCS SBOM bytes while strictly enforcing ``max_bytes``."""
    has_gzip_magic = raw[:2] == b"\x1f\x8b"
    expects_gzip = object_label.lower().endswith(".gz") or (
        content_encoding is not None and "gzip" in content_encoding.lower()
    )
    already_plain_json = not has_gzip_magic and raw.lstrip()[:1] in (b"{", b"[")
    if not has_gzip_magic and (not expects_gzip or already_plain_json):
        if len(raw) > max_bytes:
            raise BackendQueryError(
                f"[{backend_name}] GCS object {object_label} exceeds limit {max_bytes} bytes."
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
    """Decode UTF-8 JSON object from a GCP API response guarding against deep nesting."""
    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BackendQueryError(
            f"[{backend_name}] Invalid JSON response from {url}: {exc}"
        ) from exc
    if not isinstance(decoded, dict):
        raise BackendQueryError(f"[{backend_name}] Expected JSON object from {url}.")
    return decoded


def validate_gcs_bucket(bucket: str, *, field_name: str = "bucket") -> str:
    """Validate a GCS bucket name against GCS bucket naming rules."""
    cleaned = validate_no_control_chars(bucket, field_name=field_name, max_length=222)
    if ".." in cleaned or not GCS_BUCKET_RE.fullmatch(cleaned):
        raise BackendConfigError(f"Invalid GCS bucket name: {bucket!r}.")
    return cleaned


def validate_gcs_bucket_allowlist(buckets: Sequence[str]) -> tuple[str, ...]:
    """Validate a sequence of allowed GCS bucket names for SBOM_REFERENCE lookups."""
    return tuple(validate_gcs_bucket(b, field_name="allowed_sbom_buckets") for b in buckets)


def parse_gs_uri(uri: str, *, backend_name: str) -> tuple[str, str]:
    """Strictly parse a ``gs://<bucket>/<object>`` URI and reject non-GCS/traversal targets."""
    if not isinstance(uri, str) or any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in uri):
        raise BackendQueryError(f"[{backend_name}] Invalid or control-character SBOM URI {uri!r}.")
    cleaned = uri.strip()
    if not cleaned.startswith("gs://"):
        raise BackendQueryError(
            f"[{backend_name}] Refusing non-gs:// SBOM_REFERENCE location {cleaned!r}."
        )
    remainder = cleaned[len("gs://") :]
    if "/" not in remainder:
        raise BackendQueryError(f"[{backend_name}] Malformed gs:// URI {cleaned!r}.")
    bucket_part, object_part = remainder.split("/", 1)
    if ".." in bucket_part or not GCS_BUCKET_RE.fullmatch(bucket_part):
        raise BackendQueryError(f"[{backend_name}] Invalid GCS bucket in URI {cleaned!r}.")
    if not object_part or "\\" in object_part or any(seg == ".." for seg in object_part.split("/")):
        raise BackendQueryError(
            f"[{backend_name}] Invalid or traversal GCS object path in URI {cleaned!r}."
        )
    return bucket_part, object_part
