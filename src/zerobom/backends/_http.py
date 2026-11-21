"""Shared internal HTTP transport, TLS, URL, and option helpers for built-in backends."""

from __future__ import annotations

import math
import os
import ssl
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from zerobom.backends.base import BackendConfigError, BackendQueryError

MAX_API_URL_LENGTH = 2048
DEFAULT_API_TIMEOUT_SECONDS = 15.0
MAX_API_TIMEOUT_SECONDS = 120.0
DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024
REDIRECT_STATUS_CODES: frozenset[int] = frozenset({301, 302, 303, 307, 308})


def validate_no_control_chars(
    value: Any,
    *,
    field_name: str,
    max_length: int = 2048,
    allow_empty: bool = False,
) -> str:
    """Validate that an untrusted config value is a bounded string free of control characters.

    Args:
        value: Untrusted input value.
        field_name: Field label used in diagnostic exceptions.
        max_length: Maximum permitted string length after stripping.
        allow_empty: When ``True``, permit empty strings after stripping.

    Returns:
        Validated and whitespace-trimmed string.

    Raises:
        BackendConfigError: If ``value`` is not a string, contains ASCII control characters,
            exceeds ``max_length``, or is empty when ``allow_empty=False``.
    """
    if not isinstance(value, str):
        raise BackendConfigError(f"Configuration option {field_name!r} must be a string.")
    # Check control chars before stripping so trailing CR/LF/NUL are never silently dropped.
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise BackendConfigError(
            f"Configuration option {field_name!r} must not contain control characters."
        )
    cleaned = value.strip()
    if not allow_empty and not cleaned:
        raise BackendConfigError(f"Configuration option {field_name!r} must not be empty.")
    if len(cleaned) > max_length:
        raise BackendConfigError(
            f"Configuration option {field_name!r} exceeds maximum length of {max_length} chars."
        )
    return cleaned


def validate_api_base_url(
    url: Any,
    *,
    allow_insecure_http: bool = False,
    field_name: str = "base_url",
    allow_query: bool = False,
) -> str:
    """Validate and normalize an HTTPS (or opted-in HTTP) API endpoint URL.

    Args:
        url: Candidate URL string.
        allow_insecure_http: Permit ``http://`` URLs when explicitly opted in for local/dev use.
        field_name: Configuration field name for clear diagnostics.
        allow_query: Permit URL query components (used e.g. for OCI Bearer auth realm URLs).

    Returns:
        Normalized URL string without fragments (and without trailing ``/`` when
        ``allow_query=False``).

    Raises:
        BackendConfigError: If the URL violates scheme, credential, length, or syntax rules.
    """
    cleaned = validate_no_control_chars(
        url,
        field_name=field_name,
        max_length=MAX_API_URL_LENGTH,
    )
    if any(ch.isspace() for ch in cleaned):
        raise BackendConfigError(
            f"Configuration option {field_name!r} must not contain whitespace."
        )

    parsed = urlsplit(cleaned)
    scheme = parsed.scheme.lower()
    allowed_schemes = {"https", "http"} if allow_insecure_http else {"https"}
    if scheme not in allowed_schemes:
        if scheme == "http" and not allow_insecure_http:
            raise BackendConfigError(
                f"{field_name!r} requires https:// (set allow_insecure_http=true to permit http://)."
            )
        raise BackendConfigError(f"{field_name!r} must use scheme in {sorted(allowed_schemes)}.")

    if not parsed.hostname:
        raise BackendConfigError(f"{field_name!r} must include a valid hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise BackendConfigError(f"{field_name!r} must not embed credentials in the URL.")
    if parsed.fragment:
        raise BackendConfigError(f"{field_name!r} must not contain a URL fragment.")
    if parsed.query and not allow_query:
        raise BackendConfigError(f"{field_name!r} must not contain query parameters.")
    if "\\" in parsed.path:
        raise BackendConfigError(f"{field_name!r} must not contain backslashes.")

    path_segments = [seg for seg in parsed.path.split("/") if seg]
    if any(seg in {".", ".."} for seg in path_segments):
        raise BackendConfigError(f"{field_name!r} must not contain path traversal segments.")

    normalized_path = parsed.path if allow_query else parsed.path.rstrip("/")
    query = parsed.query if allow_query else ""
    return urlunsplit((scheme, parsed.netloc, normalized_path, query, ""))


def _validate_existing_file(raw_path: str | Path, *, field_name: str) -> Path:
    """Validate that a configured TLS certificate or key path refers to an existing file."""
    path_str = validate_no_control_chars(
        str(raw_path),
        field_name=field_name,
        max_length=2048,
    )
    path = Path(path_str)
    if not path.is_file():
        raise BackendConfigError(
            f"Configured {field_name} path does not exist or is not a file: {path}"
        )
    return path


def resolve_tls_verify(
    *,
    verify_tls: bool = True,
    ca_bundle: str | Path | None = None,
    ca_pem_data: str | None = None,
    client_cert: str | Path | None = None,
    client_key: str | Path | None = None,
) -> bool | ssl.SSLContext:
    """Build an ``httpx``-compatible TLS verification setting from backend config.

    Always returns either ``bool`` or an explicit ``ssl.SSLContext`` (never raw file path
    strings, avoiding ``httpx`` 0.28+ deprecation warnings).

    Args:
        verify_tls: Whether server TLS certificates must be verified.
        ca_bundle: Optional filesystem path to a PEM CA bundle file.
        ca_pem_data: Optional inline PEM CA certificate text.
        client_cert: Optional client certificate PEM file path for mutual TLS.
        client_key: Optional client private key PEM file path for mutual TLS.

    Returns:
        ``bool`` or configured :class:`ssl.SSLContext`.

    Raises:
        BackendConfigError: If conflicting TLS options, missing files, or invalid PEMs occur.
    """
    if (client_cert is None) != (client_key is None):
        raise BackendConfigError("Both client_cert and client_key must be provided together.")
    if ca_bundle is not None and ca_pem_data is not None:
        raise BackendConfigError("Specify either ca_bundle or ca_pem_data, not both.")
    if not verify_tls and (ca_bundle is not None or ca_pem_data is not None):
        raise BackendConfigError("Cannot combine verify_tls=False with a custom CA bundle.")
    if not verify_tls and (client_cert is not None or client_key is not None):
        raise BackendConfigError(
            "Cannot combine verify_tls=False with client certificate authentication."
        )

    if not verify_tls:
        return False

    if ca_bundle is None and ca_pem_data is None and client_cert is None:
        return True

    try:
        if ca_bundle is not None:
            ca_path = _validate_existing_file(ca_bundle, field_name="ca_bundle")
            ctx = ssl.create_default_context(cafile=str(ca_path))
        elif ca_pem_data is not None:
            if not isinstance(ca_pem_data, str) or "\x00" in ca_pem_data or not ca_pem_data.strip():
                raise BackendConfigError("ca_pem_data must be valid non-empty PEM text.")
            if len(ca_pem_data) > 1024 * 1024:
                raise BackendConfigError("ca_pem_data exceeds maximum size of 1 MiB.")
            ctx = ssl.create_default_context(cadata=ca_pem_data)
        else:
            ctx = ssl.create_default_context()

        if client_cert is not None and client_key is not None:
            cert_path = _validate_existing_file(client_cert, field_name="client_cert")
            key_path = _validate_existing_file(client_key, field_name="client_key")
            ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    except BackendConfigError:
        raise
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise BackendConfigError(f"Invalid TLS configuration: {exc}") from exc

    return ctx


def redact_url_for_error(url: str, *, redact_path: bool = False) -> str:
    """Return a sanitized URL safe for error messages and logs without secrets or queries.

    Strips query parameters and URL fragments (which commonly hold Azure SAS tokens or
    presigned URL credentials), and optionally redacts path segments (for webhook endpoints
    whose secret bearer token is encoded in the path).
    """
    parsed = urlsplit(url)
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc
    if not netloc:
        return "<redacted-url>"
    path = "/..." if redact_path else parsed.path
    return urlunsplit((scheme, netloc, path, "", ""))


def read_bounded_response(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    params: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    json_body: Any | None = None,
    auth: httpx.Auth | tuple[str, str] | None = None,
    backend_name: str = "backend",
    redact_url_path: bool = False,
) -> tuple[int, httpx.Headers, bytes]:
    """Execute an HTTP request and read the response body with an explicit byte ceiling.

    Args:
        client: Pre-configured :class:`httpx.Client` (must disable auto-redirects).
        method: HTTP verb (typically ``"GET"`` or ``"POST"``).
        url: Validated target URL.
        max_bytes: Maximum permitted response payload size in bytes.
        params: Optional query string parameters.
        headers: Optional request headers.
        json_body: Optional JSON-serializable request payload.
        auth: Optional per-request HTTP authentication tuple or ``httpx.Auth``.
        backend_name: Backend label for clear error diagnostics.
        redact_url_path: When ``True``, mask the URL path in diagnostic error messages
            (e.g., for secret-bearing Slack/generic webhook paths).

    Returns:
        Tuple of ``(status_code, response_headers, body_bytes)``.

    Raises:
        ValueError: If ``max_bytes < 1``.
        BackendQueryError: On transport failure, invalid Content-Length, or size overflow.
    """
    if max_bytes < 1:
        raise ValueError("max_bytes must be >= 1")

    safe_url = redact_url_for_error(url, redact_path=redact_url_path)

    try:
        stream_ctx = (
            client.stream(method, url, params=params, headers=headers, json=json_body, auth=auth)
            if auth is not None
            else client.stream(method, url, params=params, headers=headers, json=json_body)
        )
        with stream_ctx as response:
            raw_content_length = response.headers.get("content-length")
            if raw_content_length is not None:
                cl_str = raw_content_length.strip()
                if cl_str.isdigit() and int(cl_str) > max_bytes:
                    raise BackendQueryError(
                        f"[{backend_name}] Response Content-Length ({cl_str} bytes) exceeds "
                        f"limit of {max_bytes} bytes for {safe_url}."
                    )

            buf = bytearray()
            for chunk in response.iter_bytes():
                if len(buf) + len(chunk) > max_bytes:
                    raise BackendQueryError(
                        f"[{backend_name}] Response payload exceeds limit of "
                        f"{max_bytes} bytes for {safe_url}."
                    )
                buf.extend(chunk)

            return response.status_code, response.headers, bytes(buf)
    except BackendQueryError:
        raise
    except httpx.HTTPError as exc:
        # Omit raw exception message to prevent leaking query secrets (?sig=...) or webhook paths.
        raise BackendQueryError(
            f"[{backend_name}] HTTP request failed ({type(exc).__name__}) for {safe_url}."
        ) from exc


def reject_unknown_config_keys(
    config: Mapping[str, Any],
    allowed_keys: frozenset[str],
    *,
    backend_name: str,
) -> None:
    """Fail closed when unrecognized keys are passed in backend configuration."""
    unknown = sorted(set(config.keys()) - allowed_keys)
    if unknown:
        raise BackendConfigError(
            f"Unsupported configuration option(s) for {backend_name!r}: {', '.join(unknown)}."
        )


def parse_bool_opt(config: Mapping[str, Any], key: str, *, default: bool) -> bool:
    """Parse a boolean option from native YAML/JSON types or CLI ``key=value`` strings."""
    if key not in config or config[key] is None:
        return default
    raw = config[key]
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        normalized = raw.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    raise BackendConfigError(f"Configuration option {key!r} must be a boolean.")


def parse_int_opt(
    config: Mapping[str, Any],
    key: str,
    *,
    default: int,
    min_value: int,
    max_value: int,
) -> int:
    """Parse a bounded integer option from native ints or decimal strings."""
    if key not in config or config[key] is None:
        return default
    raw = config[key]
    if isinstance(raw, bool):
        raise BackendConfigError(f"Configuration option {key!r} must be an integer.")
    try:
        if isinstance(raw, int):
            val = raw
        elif isinstance(raw, str):
            val = int(raw.strip())
        else:
            raise ValueError("non-integer type")
    except ValueError as exc:
        raise BackendConfigError(f"Configuration option {key!r} must be an integer.") from exc

    if not math.isfinite(val) or val < min_value or val > max_value:
        raise BackendConfigError(
            f"Configuration option {key!r} must be between {min_value} and {max_value}."
        )
    return val


def parse_float_opt(
    config: Mapping[str, Any],
    key: str,
    *,
    default: float,
    min_value: float,
    max_value: float,
) -> float:
    """Parse a bounded numeric float option from numbers or strings."""
    if key not in config or config[key] is None:
        return default
    raw = config[key]
    if isinstance(raw, bool):
        raise BackendConfigError(f"Configuration option {key!r} must be a number.")
    try:
        if isinstance(raw, (int, float)):
            val = float(raw)
        elif isinstance(raw, str):
            val = float(raw.strip())
        else:
            raise ValueError("non-numeric type")
    except ValueError as exc:
        raise BackendConfigError(f"Configuration option {key!r} must be a number.") from exc

    if not math.isfinite(val) or val < min_value or val > max_value:
        raise BackendConfigError(
            f"Configuration option {key!r} must be between {min_value} and {max_value}."
        )
    return val


def parse_optional_str_opt(
    config: Mapping[str, Any],
    key: str,
    *,
    env_var: str | None = None,
    max_length: int = 2048,
    allow_empty: bool = False,
) -> str | None:
    """Read an optional string config option with optional environment variable fallback."""
    if key in config and config[key] is not None:
        return validate_no_control_chars(
            config[key],
            field_name=key,
            max_length=max_length,
            allow_empty=allow_empty,
        )
    if env_var is not None:
        env_val = os.environ.get(env_var)
        if env_val is not None and env_val.strip():
            return validate_no_control_chars(
                env_val,
                field_name=env_var,
                max_length=max_length,
            )
    return None


def parse_str_list_opt(
    config: Mapping[str, Any],
    key: str,
    *,
    max_items: int = 100,
    max_item_length: int = 512,
) -> tuple[str, ...]:
    """Parse a string list option from a YAML/JSON sequence or comma-separated string."""
    if key not in config or config[key] is None:
        return ()
    raw = config[key]
    items: list[str] = []
    if isinstance(raw, str):
        # Validate the unsplit string first so CR/LF around whitespace is never stripped silently.
        checked_raw = validate_no_control_chars(
            raw,
            field_name=key,
            max_length=max_items * (max_item_length + 2),
            allow_empty=True,
        )
        for part in checked_raw.split(","):
            stripped = part.strip()
            if stripped:
                items.append(
                    validate_no_control_chars(
                        stripped,
                        field_name=key,
                        max_length=max_item_length,
                    )
                )
    elif isinstance(raw, Sequence) and not isinstance(raw, (bytes, bytearray)):
        for elem in raw:
            items.append(
                validate_no_control_chars(
                    elem,
                    field_name=key,
                    max_length=max_item_length,
                )
            )
    else:
        raise BackendConfigError(
            f"Configuration option {key!r} must be a list of strings or comma-separated string."
        )

    if len(items) > max_items:
        raise BackendConfigError(
            f"Configuration option {key!r} exceeds maximum count of {max_items} items."
        )
    return tuple(items)


def validate_bounded_int(
    value: Any,
    *,
    field_name: str,
    min_value: int,
    max_value: int,
) -> int:
    """Validate that ``value`` is a strict non-boolean integer within inclusive bounds."""
    if isinstance(value, bool) or not isinstance(value, int) or not min_value <= value <= max_value:
        raise BackendConfigError(
            f"Configuration option {field_name!r} must be between {min_value} and {max_value}."
        )
    return value


def validate_timeout_seconds(value: Any) -> float:
    """Validate an HTTP request timeout in ``0.5..MAX_API_TIMEOUT_SECONDS`` seconds."""
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0.5 <= float(value) <= MAX_API_TIMEOUT_SECONDS
    ):
        raise BackendConfigError(
            f"Configuration option 'timeout_seconds' must be between "
            f"0.5 and {MAX_API_TIMEOUT_SECONDS}."
        )
    return float(value)
