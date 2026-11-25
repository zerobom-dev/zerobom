"""SSRF-hardened HTTP fetcher and article text extraction using ``httpx`` and ``trafilatura``.

All outbound URLs undergo strict scheme, credential, length, and DNS-resolved IP address
validation prior to connection and on every HTTP redirect hop. Non-global targets (loopback,
RFC 1918 private, link-local / cloud IMDS ``169.254.169.254``, multicast, reserved, and
IPv4-mapped IPv6 variants) fail closed with :class:`SsrfBlockedError`.
"""

from __future__ import annotations

import hashlib
import html as html_lib
import ipaddress
import re
import socket
import warnings
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urljoin, urlparse

import httpx

from zerobom._version import DEFAULT_USER_AGENT
from zerobom.models import RawArticle, SourceTier

MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_REDIRECTS = 3
DEFAULT_TIMEOUT_SECONDS = 15.0
MAX_FETCH_URL_LENGTH = 2048

ALLOWED_FETCH_SCHEMES: frozenset[str] = frozenset({"http", "https"})
ALLOWED_CONTENT_TYPES: frozenset[str] = frozenset(
    {
        "text/html",
        "application/xhtml+xml",
        "text/plain",
        "application/xml",
        "text/xml",
        "application/rss+xml",
        "application/atom+xml",
    }
)
_REDIRECT_STATUS_CODES: frozenset[int] = frozenset({301, 302, 303, 307, 308})

_TITLE_TAG_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_SCRIPT_STYLE_RE = re.compile(r"<(?:script|style)[^>]*>.*?</(?:script|style)>", re.I | re.S)
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")

DnsResolver = Callable[[str, int], Sequence[str]]


class FetchError(RuntimeError):
    """Raised when fetching or decoding a remote feed or article fails safely."""


class SsrfBlockedError(FetchError):
    """Raised when a URL or redirect target resolves to a non-public IP address."""


@dataclass(frozen=True)
class FetchResponse:
    """Bounded HTTP response payload returned by :class:`SafeHttpFetcher`.

    Attributes:
        final_url: Final validated URL after any permitted redirects.
        status_code: HTTP status code.
        content_type: Normalized MIME type (without charset parameters).
        body: Raw response bytes (empty on ``304 Not Modified``).
        etag: Optional HTTP ``ETag`` response header.
        last_modified: Optional HTTP ``Last-Modified`` response header.
        not_modified: True when the server responded with HTTP ``304 Not Modified``.
    """

    final_url: str
    status_code: int
    content_type: str
    body: bytes
    etag: str | None = None
    last_modified: str | None = None
    not_modified: bool = False


def default_dns_resolver(hostname: str, port: int) -> tuple[str, ...]:
    """Resolve ``hostname`` to unique IP address strings via the system resolver."""
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise FetchError(f"DNS resolution failed for host {hostname!r}: {exc}") from exc

    ips: list[str] = []
    seen: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_str = str(sockaddr[0])
        # Strip IPv6 zone identifier if present (e.g., fe80::1%eth0).
        ip_clean = ip_str.split("%", 1)[0]
        if ip_clean not in seen:
            seen.add(ip_clean)
            ips.append(ip_clean)
    return tuple(ips)


def is_public_ip(ip_str: str) -> bool:
    """Return True only when ``ip_str`` is a globally routable public IP address.

    Unwraps IPv4-mapped IPv6 addresses (e.g., ``::ffff:169.254.169.254``) and blocks private,
    loopback, link-local (cloud IMDS), multicast, reserved, and unspecified ranges.

    Args:
        ip_str: IPv4 or IPv6 literal string.

    Returns:
        ``True`` if globally routable; ``False`` otherwise.
    """
    cleaned = ip_str.strip().split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(cleaned)
    except ValueError:
        return False

    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip.sixtofour is not None and not ip.sixtofour.is_global:
            return False

    return bool(
        ip.is_global
        and not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    )


def validate_fetch_url(
    url: str,
    *,
    dns_resolver: DnsResolver = default_dns_resolver,
) -> str:
    """Validate URL syntax, scheme, absence of credentials, and DNS-resolved IPs.

    Args:
        url: Untrusted HTTP or HTTPS URL candidate.
        dns_resolver: Callable mapping ``(hostname, port)`` to resolved IP strings.

    Returns:
        Validated trimmed URL string.

    Raises:
        FetchError: If URL syntax, scheme, credentials, or DNS resolution fails.
        SsrfBlockedError: If the host or any resolved IP is non-global/internal.
    """
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise FetchError("Fetch URL must not contain control characters.")

    stripped = url.strip()
    if not stripped or len(stripped) > MAX_FETCH_URL_LENGTH:
        raise FetchError("Fetch URL is empty or exceeds maximum length.")
    if any(ch.isspace() for ch in stripped):
        raise FetchError("Fetch URL must not contain whitespace.")

    parsed = urlparse(stripped)
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_FETCH_SCHEMES:
        raise FetchError(f"Disallowed URL scheme {parsed.scheme!r}; only http/https permitted.")
    if parsed.username is not None or parsed.password is not None:
        raise FetchError("URLs containing embedded credentials are forbidden.")

    hostname = parsed.hostname
    if not hostname:
        raise FetchError("Fetch URL must contain a valid hostname.")

    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise FetchError(f"Invalid port in URL {stripped!r}: {exc}") from exc

    # Fail immediately on literal non-public IP hosts before invoking DNS.
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        if not is_public_ip(hostname):
            raise SsrfBlockedError(f"Blocked non-public literal IP host {hostname!r}.")

    resolved_ips = dns_resolver(hostname, port)
    if not resolved_ips:
        raise FetchError(f"DNS resolution returned no addresses for {hostname!r}.")

    for ip_str in resolved_ips:
        if not is_public_ip(ip_str):
            raise SsrfBlockedError(
                f"Blocked SSRF target: host {hostname!r} resolved to non-public IP {ip_str!r}."
            )

    return stripped


def _strip_disallowed_control_chars(text: str) -> str:
    """Keep printable text plus tabs/newlines while stripping C0/C1 control artifacts."""
    return "".join(
        ch for ch in text if ch in {"\n", "\t"} or (ord(ch) >= 32 and not (127 <= ord(ch) <= 159))
    ).strip()


def _fallback_html_to_text(html: str) -> str:
    """Minimal safe HTML-to-text fallback when trafilatura yields None on short fragments."""
    without_scripts = _SCRIPT_STYLE_RE.sub(" ", html)
    without_tags = _HTML_TAG_RE.sub(" ", without_scripts)
    unescaped = html_lib.unescape(without_tags)
    return _WHITESPACE_RE.sub(" ", unescaped).strip()


def _parse_html_metadata_date(
    raw_date: object,
    *,
    now: datetime | None = None,
) -> datetime | None:
    """Parse an HTML metadata publication date into bounded UTC, if valid.

    Args:
        raw_date: Candidate metadata date value returned by ``trafilatura``.
        now: Reference timestamp for future-date sanity checks. Defaults to UTC now.

    Returns:
        Normalized UTC datetime when ``raw_date`` parses as ISO-8601/YYYY-MM-DD and falls
        within ``[1990-01-01, now + 2 days]``; otherwise ``None``.
    """
    if isinstance(raw_date, datetime):
        parsed = (
            raw_date.replace(tzinfo=UTC) if raw_date.tzinfo is None else raw_date.astimezone(UTC)
        )
    elif isinstance(raw_date, str):
        candidate = raw_date.strip()
        if not candidate:
            return None
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            return None
        parsed = parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    else:
        return None

    ref_now = now or datetime.now(UTC)
    if parsed.year < 1990 or parsed > ref_now + timedelta(days=2):
        return None
    return parsed


def extract_article_metadata_and_text(
    raw_bytes: bytes,
    content_type: str,
    *,
    fallback_title: str = "Untitled Advisory",
) -> tuple[str, str, datetime | None]:
    """Extract sanitized title, plain-text body, and optional publication date.

    Args:
        raw_bytes: Raw downloaded document payload.
        content_type: Normalized HTTP Content-Type media type.
        fallback_title: Title used when extraction yields no usable title.

    Returns:
        Tuple of ``(clean_title, clean_body, extracted_published_at)``.
    """
    decoded = raw_bytes.decode("utf-8", errors="replace")
    media_type = content_type.split(";", 1)[0].strip().lower()

    if media_type == "text/plain":
        return fallback_title, _strip_disallowed_control_chars(decoded), None

    # Lazy-import trafilatura here to keep CLI startup fast and suppress urllib3's benign
    # PySocks DependencyWarning emitted on module import.
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message=".*SOCKS support in urllib3.*")
        import trafilatura

    extracted = trafilatura.extract(
        decoded,
        include_comments=False,
        include_tables=True,
        favor_recall=True,
    )
    body = extracted if extracted and extracted.strip() else _fallback_html_to_text(decoded)

    title: str | None = None
    metadata = trafilatura.extract_metadata(decoded)
    meta_title = getattr(metadata, "title", None) if metadata is not None else None
    meta_date = getattr(metadata, "date", None) if metadata is not None else None
    extracted_published_at = _parse_html_metadata_date(meta_date)
    if isinstance(meta_title, str) and meta_title.strip():
        title = meta_title.strip()
    elif title_match := _TITLE_TAG_RE.search(decoded):
        candidate = _WHITESPACE_RE.sub(" ", html_lib.unescape(title_match.group(1))).strip()
        if candidate:
            title = candidate

    raw_title = _WHITESPACE_RE.sub(" ", _strip_disallowed_control_chars(title or fallback_title))
    clean_title = raw_title.strip() or fallback_title
    clean_body = _strip_disallowed_control_chars(body)
    return clean_title, clean_body, extracted_published_at


def extract_article_text(
    raw_bytes: bytes,
    content_type: str,
    *,
    fallback_title: str = "Untitled Advisory",
) -> tuple[str, str]:
    """Extract clean ``(title, body)`` text from fetched HTML or plain-text bytes.

    Args:
        raw_bytes: Downloaded response bytes.
        content_type: Normalized MIME content type.
        fallback_title: Title used when HTML lacks extractable title metadata.

    Returns:
        Tuple of ``(title, cleaned_body)``.
    """
    title, body, _ = extract_article_metadata_and_text(
        raw_bytes,
        content_type,
        fallback_title=fallback_title,
    )
    return title, body


def compute_content_sha256(text: str) -> str:
    """Compute a deterministic SHA-256 hex digest over whitespace-normalized text.

    Args:
        text: Extracted article body text.

    Returns:
        Lowercase 64-character hexadecimal SHA-256 digest.
    """
    normalized = _WHITESPACE_RE.sub(" ", text).strip().encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()


class SafeHttpFetcher:
    """SSRF-hardened, streaming-bounded HTTP fetcher with manual redirect verification."""

    def __init__(
        self,
        *,
        client: httpx.Client | None = None,
        dns_resolver: DnsResolver | None = None,
        max_bytes: int = MAX_RESPONSE_BYTES,
        max_redirects: int = MAX_REDIRECTS,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        """Initialize the hardened HTTP fetcher.

        Args:
            client: Optional pre-configured ``httpx.Client`` (e.g., ``MockTransport`` in tests).
            dns_resolver: Optional DNS resolver callable for deterministic offline testing.
            max_bytes: Maximum allowed streamed response payload size in bytes.
            max_redirects: Maximum permitted HTTP redirect hops (each hop re-validated).
            timeout: Socket/request timeout in seconds for default client creation.

        Raises:
            ValueError: If ``max_bytes < 1`` or ``max_redirects < 0``.
        """
        if max_bytes < 1:
            raise ValueError("max_bytes must be >= 1")
        if max_redirects < 0:
            raise ValueError("max_redirects must be >= 0")

        self._owns_client = client is None
        # Disable automatic redirects so every Location hop is SSRF-checked first.
        self._client = (
            client
            if client is not None
            else httpx.Client(
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
                headers={"User-Agent": DEFAULT_USER_AGENT},
            )
        )
        self._dns_resolver: DnsResolver = dns_resolver or default_dns_resolver
        self._max_bytes = max_bytes
        self._max_redirects = max_redirects

    @property
    def client(self) -> httpx.Client:
        """Return the underlying ``httpx.Client`` instance."""
        return self._client

    def close(self) -> None:
        """Close the underlying HTTP client when owned by this instance."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> SafeHttpFetcher:
        """Enter context manager scope."""
        return self

    def __exit__(self, *_: object) -> None:
        """Close owned HTTP resources upon exit."""
        self.close()

    def fetch_bytes(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        allowed_content_types: frozenset[str] = ALLOWED_CONTENT_TYPES,
    ) -> FetchResponse:
        """Fetch raw response bytes with per-hop SSRF validation and streaming size limits.

        Args:
            url: Target HTTP or HTTPS URL.
            headers: Optional extra request headers (e.g., ``If-None-Match``).
            allowed_content_types: Permitted normalized MIME media types.

        Returns:
            A :class:`FetchResponse` containing validated payload bytes and cache headers.

        Raises:
            SsrfBlockedError: If the initial URL or any redirect resolves to a non-public IP.
            FetchError: On HTTP error status, disallowed Content-Type, redirect loop, or size cap.
        """
        current_url = url
        request_headers = dict(headers) if headers else {}

        for hop in range(self._max_redirects + 1):
            validated_url = validate_fetch_url(current_url, dns_resolver=self._dns_resolver)

            try:
                with self._client.stream(
                    "GET",
                    validated_url,
                    headers=request_headers if hop == 0 else {},
                ) as response:
                    etag = response.headers.get("etag")
                    last_modified = response.headers.get("last-modified")

                    if response.status_code == 304:
                        return FetchResponse(
                            final_url=validated_url,
                            status_code=304,
                            content_type="",
                            body=b"",
                            etag=etag,
                            last_modified=last_modified,
                            not_modified=True,
                        )

                    if response.status_code in _REDIRECT_STATUS_CODES:
                        location = response.headers.get("location")
                        if not location:
                            raise FetchError(
                                f"Redirect ({response.status_code}) missing Location header."
                            )
                        if any(ord(ch) < 32 or ord(ch) == 127 for ch in location):
                            raise FetchError("Redirect Location header contains control chars.")
                        if hop >= self._max_redirects:
                            raise FetchError(
                                f"Exceeded maximum redirect limit ({self._max_redirects})."
                            )
                        current_url = urljoin(validated_url, location.strip())
                        continue

                    if response.status_code >= 400:
                        raise FetchError(
                            f"HTTP {response.status_code} returned while fetching {validated_url}."
                        )

                    raw_ct = response.headers.get("content-type", "")
                    media_type = raw_ct.split(";", 1)[0].strip().lower()
                    if allowed_content_types and media_type not in allowed_content_types:
                        raise FetchError(
                            f"Disallowed Content-Type {media_type or 'missing'!r} "
                            f"from {validated_url}."
                        )

                    content_len = response.headers.get("content-length")
                    if content_len is not None:
                        try:
                            declared = int(content_len)
                        except ValueError as exc:
                            raise FetchError(
                                f"Invalid Content-Length header {content_len!r}."
                            ) from exc
                        if declared > self._max_bytes:
                            raise FetchError(
                                f"Declared Content-Length ({declared} bytes) exceeds limit "
                                f"({self._max_bytes} bytes)."
                            )

                    chunks: list[bytes] = []
                    total_bytes = 0
                    for chunk in response.iter_bytes():
                        total_bytes += len(chunk)
                        if total_bytes > self._max_bytes:
                            raise FetchError(
                                f"Response stream exceeded max_bytes={self._max_bytes}."
                            )
                        chunks.append(chunk)

                    return FetchResponse(
                        final_url=validated_url,
                        status_code=response.status_code,
                        content_type=media_type,
                        body=b"".join(chunks),
                        etag=etag,
                        last_modified=last_modified,
                        not_modified=False,
                    )
            except FetchError:
                raise
            except httpx.HTTPError as exc:
                raise FetchError(f"HTTP transport error fetching {validated_url}: {exc}") from exc

        raise FetchError(f"Exceeded maximum redirect limit ({self._max_redirects}).")

    def fetch_article(
        self,
        url: str,
        *,
        source_name: str,
        source_tier: SourceTier = SourceTier.UNKNOWN,
        published_at: datetime | None = None,
        published_at_inferred: bool = False,
        conditional_headers: dict[str, str] | None = None,
    ) -> tuple[RawArticle | None, FetchResponse]:
        """Fetch an HTML/text blog post and extract a normalized :class:`RawArticle`.

        Args:
            url: Source article HTTP/HTTPS URL.
            source_name: Human-readable feed/publisher name.
            source_tier: Source credibility tier.
            published_at: Optional publication timestamp (defaults to current UTC time).
            published_at_inferred: Whether ``published_at`` was synthesized rather than stated in
                feed/sitemap metadata.
            conditional_headers: Optional ``If-None-Match`` / ``If-Modified-Since`` headers.

        Returns:
            Tuple of ``(RawArticle | None, FetchResponse)``. The article is ``None`` when the
            server replies ``304 Not Modified``.

        Raises:
            FetchError: On transport, SSRF, content-type, or empty-body failure.
        """
        resp = self.fetch_bytes(url, headers=conditional_headers)
        if resp.not_modified:
            return None, resp

        title, body, html_published_at = extract_article_metadata_and_text(
            resp.body,
            resp.content_type,
        )
        if not body:
            raise FetchError(f"Extracted article body was empty for {resp.final_url}.")

        now = datetime.now(UTC)
        resolved_published_at = published_at
        resolved_inferred = published_at_inferred
        if (published_at is None or published_at_inferred) and html_published_at is not None:
            resolved_published_at = html_published_at
            resolved_inferred = False
        elif resolved_published_at is None:
            resolved_published_at = now
            resolved_inferred = True

        article = RawArticle(
            url=resp.final_url,
            title=title,
            body=body,
            source_name=source_name,
            source_tier=source_tier,
            published_at=resolved_published_at,
            published_at_inferred=resolved_inferred,
            fetched_at=now,
        )
        return article, resp
