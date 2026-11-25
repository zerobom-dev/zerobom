"""Canonical PURL resolution, generic-name blocking, and cached registry checks.

All untrusted package identifiers, namespaces, and PURLs are validated against strict
ecosystem-specific character allowlists before constructing PURLs or issuing outbound HTTP
requests. Key defenses implemented here include:

- **Generic-Name Blocklist:** Blocks ambiguous single-word names (e.g., ``core``, ``utils``,
  ``app``) unless qualified by a non-distro package namespace.
- **Path-Traversal & URL-Injection Guards:** Rejects ASCII control characters, backslashes,
  query/fragment delimiters, and dot-segments (``.``, ``..``) in package coordinates.
- **Solr Query-Injection Prevention:** Validates Maven coordinates strictly before building
  Maven Central search queries.
- **SSRF / Redirect Defense:** Disables automatic HTTP redirects by default and uses a
  parameterized SQLite cache (``?`` placeholders) to store only ``EXISTS``/``NOT_FOUND``.
"""

from __future__ import annotations

import re
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, overload
from urllib.parse import quote

import httpx
from packageurl import PackageURL

from zerobom._version import DEFAULT_USER_AGENT
from zerobom.models import ExtractedPackageClaim, PurlResolutionResult, RegistryStatus

MAX_PACKAGE_INPUT_LENGTH = 256

# Maps normalized lowercase ecosystem aliases -> (canonical PURL type, OSV ecosystem name).
ECOSYSTEM_ALIASES: dict[str, tuple[str, str]] = {
    "pypi": ("pypi", "PyPI"),
    "python": ("pypi", "PyPI"),
    "pip": ("pypi", "PyPI"),
    "npm": ("npm", "npm"),
    "node": ("npm", "npm"),
    "nodejs": ("npm", "npm"),
    "node.js": ("npm", "npm"),
    "javascript": ("npm", "npm"),
    "js": ("npm", "npm"),
    "maven": ("maven", "Maven"),
    "java": ("maven", "Maven"),
    "golang": ("golang", "Go"),
    "go": ("golang", "Go"),
    "deb": ("deb", "Debian"),
    "debian": ("deb", "Debian"),
    "apt": ("deb", "Debian"),
    "dpkg": ("deb", "Debian"),
    "ubuntu": ("deb", "Ubuntu"),
    "rpm": ("rpm", "Red Hat"),
    "redhat": ("rpm", "Red Hat"),
    "red hat": ("rpm", "Red Hat"),
    "rhel": ("rpm", "Red Hat"),
    "fedora": ("rpm", "Red Hat"),
    "centos": ("rpm", "Red Hat"),
    "rocky": ("rpm", "Red Hat"),
    "almalinux": ("rpm", "Red Hat"),
    "apk": ("apk", "Alpine"),
    "alpine": ("apk", "Alpine"),
    "cargo": ("cargo", "crates.io"),
    "rust": ("cargo", "crates.io"),
    "crates.io": ("cargo", "crates.io"),
    "crates": ("cargo", "crates.io"),
    "gem": ("gem", "RubyGems"),
    "ruby": ("gem", "RubyGems"),
    "rubygems": ("gem", "RubyGems"),
    "nuget": ("nuget", "NuGet"),
    ".net": ("nuget", "NuGet"),
    "dotnet": ("nuget", "NuGet"),
    "csharp": ("nuget", "NuGet"),
    "composer": ("composer", "Packagist"),
    "php": ("composer", "Packagist"),
    "packagist": ("composer", "Packagist"),
    "cloudlinux": ("rpm", "CloudLinux"),
    "suse": ("rpm", "SUSE"),
    "sles": ("rpm", "SUSE"),
    "opensuse": ("rpm", "SUSE"),
    "oracle": ("rpm", "Oracle Linux"),
    "oraclelinux": ("rpm", "Oracle Linux"),
    "amzn": ("rpm", "Amazon Linux"),
    "amazon": ("rpm", "Amazon Linux"),
    "amazonlinux": ("rpm", "Amazon Linux"),
    "azurelinux": ("rpm", "Azure Linux"),
    "mariner": ("rpm", "Azure Linux"),
    "wolfi": ("apk", "Wolfi"),
    "chainguard": ("apk", "Chainguard"),
    "github": ("github", "GitHub"),
    "generic": ("generic", "Generic"),
}

_DISTRO_PURL_TYPES: frozenset[str] = frozenset({"deb", "rpm", "apk"})
_RUNTIME_FRIENDLY_PURL_TYPES: frozenset[str] = _DISTRO_PURL_TYPES | {"generic"}
_DISTRO_NAMESPACE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_NON_DISTRO_NAMESPACE_BLOCKLIST: frozenset[str] = frozenset(
    {
        "apache",
        "nginx",
        "gnu",
        "mozilla",
        "php",
        "python",
        "ruby",
        "node",
        "nodejs",
        "npm",
        "pypi",
        "maven",
        "golang",
        "cargo",
        "gem",
        "nuget",
        "composer",
        "github",
        "generic",
        "upstream",
    }
)
_DISTRO_OSV_BY_NAMESPACE: dict[str, str] = {
    "debian": "Debian",
    "ubuntu": "Ubuntu",
    "redhat": "Red Hat",
    "rhel": "Red Hat",
    "fedora": "Red Hat",
    "centos": "Red Hat",
    "rocky": "Red Hat",
    "almalinux": "Red Hat",
    "alpine": "Alpine",
    "cloudlinux": "CloudLinux",
    "suse": "SUSE",
    "sles": "SUSE",
    "opensuse": "SUSE",
    "oracle": "Oracle Linux",
    "oraclelinux": "Oracle Linux",
    "amzn": "Amazon Linux",
    "amazonlinux": "Amazon Linux",
    "azurelinux": "Azure Linux",
    "mariner": "Azure Linux",
    "wolfi": "Wolfi",
    "chainguard": "Chainguard",
}
_DEFAULT_DISTRO_NAMESPACE_BY_OSV: dict[str, str] = {
    "Ubuntu": "ubuntu",
    "CloudLinux": "cloudlinux",
    "SUSE": "suse",
    "Oracle Linux": "oracle",
    "Amazon Linux": "amzn",
    "Azure Linux": "azurelinux",
    "Wolfi": "wolfi",
    "Chainguard": "chainguard",
}

# Unnamespaced generic noise words blocked across all ecosystems unless explicitly namespaced.
GENERIC_PACKAGE_BLOCKLIST: frozenset[str] = frozenset(
    {
        "core",
        "utils",
        "util",
        "app",
        "application",
        "server",
        "client",
        "api",
        "common",
        "lib",
        "library",
        "web",
        "auth",
        "db",
        "database",
        "data",
        "test",
        "tests",
        "tools",
        "tool",
        "cli",
        "sdk",
        "config",
        "helper",
        "helpers",
        "shared",
        "base",
        "main",
        "service",
        "services",
        "module",
        "plugin",
        "runtime",
        "engine",
        "system",
        "network",
        "security",
        "admin",
        "agent",
        "proxy",
        "cache",
        "queue",
        "worker",
        "logger",
        "logging",
        "parser",
        "package",
        "project",
        "framework",
        "backend",
        "frontend",
        "platform",
        "cloud",
        "container",
        "image",
        "driver",
        "script",
        "scripts",
        "firmware",
        "software",
        "hardware",
        "device",
        "router",
        "bootloader",
        "browser",
        "model",
        "llm",
        "ai",
        "daemon",
        "endpoint",
        "dashboard",
        "console",
    }
)

# Canonical runtime/OS package names blocked only on library registries (PyPI/npm/Maven/etc.).
REGISTRY_ONLY_GENERIC_BLOCKLIST: frozenset[str] = frozenset(
    {
        "kernel",
        "node",
        "python",
        "java",
        "go",
        "rust",
        "ruby",
        "php",
    }
)

_WRAPPER_PREFIX_RE = re.compile(
    r"^(?:the|package|library|lib|module|crate|gem|component)\s+",
    re.IGNORECASE,
)
_LEADING_ECOSYSTEM_RE = re.compile(
    r"^(python|pypi|pip|node\.js|nodejs|node|npm|javascript|js|java|maven|"
    r"golang|go|debian|ubuntu|apt|dpkg|red\s+hat|redhat|rhel|rpm|fedora|"
    r"cloudlinux|suse|sles|opensuse|oraclelinux|amazonlinux|azurelinux|"
    r"alpine|apk|wolfi|chainguard|rust|cargo|crates\.io|ruby|rubygems|gem|"
    r"php|composer|packagist|nuget|\.net|dotnet|generic)\s+(.+)$",
    re.IGNORECASE,
)
_TRAILING_ECOSYSTEM_RE = re.compile(r"^(.+?)\s*\(([^()]+)\)$")
_PEP503_NORMALIZE_RE = re.compile(r"[-_.]+")

# Strict coordinate allowlists enforced prior to external HTTP registry queries.
_PYPI_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_NPM_SCOPE_RE = re.compile(r"^@[a-z0-9._-]+$")
_NPM_NAME_RE = re.compile(r"^[a-z0-9._-]+$")
_MAVEN_COORD_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_GO_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._~+-]+$")
_CARGO_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_GEM_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_NUGET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_COMPOSER_PART_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_FORBIDDEN_COORD_CHARS: frozenset[str] = frozenset({"\\", "?", "#", "'", '"', ";"})


def _has_control_chars(value: str) -> bool:
    """Return True if value contains any ASCII control character (including CRLF or NUL)."""
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _validate_coordinate_safety(value: str) -> bool:
    """Return True if a resolved namespace or package name is free of traversal/injection chars."""
    if not value or len(value) > MAX_PACKAGE_INPUT_LENGTH:
        return False
    # Reject non-ASCII homoglyphs (e.g., Cyrillic \u0456) before generic-blocklist checks.
    if not value.isascii():
        return False
    if _has_control_chars(value) or any(ch.isspace() for ch in value):
        return False
    if any(ch in _FORBIDDEN_COORD_CHARS for ch in value):
        return False
    # Reject empty, '.', or '..' path segments to defeat directory traversal.
    segments = value.split("/")
    return all(seg not in {"", ".", ".."} for seg in segments)


def normalize_ecosystem(raw: str | None) -> tuple[str | None, str | None]:
    """Normalize an ecosystem alias into ``(canonical_purl_type, osv_ecosystem)``.

    Args:
        raw: Ecosystem string or alias (e.g., ``"Python"``, ``"Node.js"``, ``"deb"``).

    Returns:
        Tuple of ``(purl_type, osv_ecosystem)``, or ``(None, None)`` if unrecognized.
    """
    if raw is None or _has_control_chars(raw):
        return None, None
    key = re.sub(r"\s+", " ", raw.strip().lower())
    if not key:
        return None, None
    return ECOSYSTEM_ALIASES.get(key, (None, None))


def _resolve_osv_ecosystem(
    purl_type: str,
    namespace: str | None,
    hinted_osv: str | None,
) -> str:
    """Determine the canonical OSV ecosystem string for an affected package."""
    if purl_type in _DISTRO_PURL_TYPES and namespace:
        lowered_ns = namespace.lower()
        ns_mapped = _DISTRO_OSV_BY_NAMESPACE.get(lowered_ns)
        if ns_mapped is not None:
            return ns_mapped
        return lowered_ns
    if hinted_osv is not None:
        return hinted_osv
    _, default_osv = normalize_ecosystem(purl_type)
    return default_osv or purl_type


def _strip_natural_language(raw_name: str) -> tuple[str, str | None]:
    """Strip wrapper words and optional leading/trailing ecosystem hints from a package name."""
    text = raw_name.strip().strip("`'\"")
    inferred_ecosystem: str | None = None

    changed = True
    while changed:
        changed = False
        wrapped = _WRAPPER_PREFIX_RE.sub("", text, count=1).strip()
        if wrapped != text:
            text = wrapped
            changed = True

    trailing_match = _TRAILING_ECOSYSTEM_RE.match(text)
    if trailing_match:
        candidate_eco = trailing_match.group(2).strip()
        purl_type, _ = normalize_ecosystem(candidate_eco)
        if purl_type is not None:
            inferred_ecosystem = candidate_eco
            text = trailing_match.group(1).strip()

    leading_match = _LEADING_ECOSYSTEM_RE.match(text)
    if leading_match:
        candidate_eco = leading_match.group(1).strip()
        remainder = leading_match.group(2).strip()
        purl_type, _ = normalize_ecosystem(candidate_eco)
        if purl_type is not None and remainder:
            if inferred_ecosystem is None:
                inferred_ecosystem = candidate_eco
            text = remainder
            # Strip wrapper words again if input read e.g. "Python package requests".
            while True:
                wrapped = _WRAPPER_PREFIX_RE.sub("", text, count=1).strip()
                if wrapped == text:
                    break
                text = wrapped

    return text, inferred_ecosystem


def _normalize_pep503(name: str) -> str:
    """Apply PEP 503 canonicalization (collapse runs of [-_.] to '-' and lowercase)."""
    return _PEP503_NORMALIZE_RE.sub("-", name).lower()


def _default_distro_namespace(purl_type: str, osv_ecosystem: str | None) -> str:
    """Return default vendor namespace for OS packages when none was explicitly provided."""
    if osv_ecosystem is not None and osv_ecosystem in _DEFAULT_DISTRO_NAMESPACE_BY_OSV:
        return _DEFAULT_DISTRO_NAMESPACE_BY_OSV[osv_ecosystem]
    if purl_type == "deb":
        return "debian"
    if purl_type == "rpm":
        return "redhat"
    if purl_type == "apk":
        return "alpine"
    return ""


def _escape_go_module(module_path: str) -> str:
    """Escape uppercase ASCII letters as ``!<lowercase>`` per the Go module proxy protocol."""
    out: list[str] = []
    for ch in module_path:
        if "A" <= ch <= "Z":
            out.append(f"!{ch.lower()}")
        else:
            out.append(ch)
    return "".join(out)


class RegistryCache(Protocol):
    """Protocol for caching package registry existence lookups."""

    def get(self, purl: str) -> RegistryStatus | None:
        """Retrieve a cached status if present and unexpired.

        Args:
            purl: Canonical Package URL string.

        Returns:
            Cached :class:`RegistryStatus` or ``None`` on cache miss/expiration.
        """

    def set(self, purl: str, status: RegistryStatus) -> None:
        """Persist a cacheable registry status for a canonical PURL.

        Args:
            purl: Canonical Package URL string.
            status: Lookup outcome (implementations should only cache definitive states).
        """


class InMemoryRegistryCache:
    """In-memory TTL cache for registry existence checks.

    Attributes:
        ttl_seconds: Maximum age in seconds before cached entries expire.
    """

    def __init__(
        self,
        ttl_seconds: float = 86400.0,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Initialize an in-memory TTL registry cache.

        Args:
            ttl_seconds: Non-negative TTL duration in seconds.
            clock: Monotonic/wall clock provider returning epoch seconds.

        Raises:
            ValueError: If ``ttl_seconds`` is negative.
        """
        if ttl_seconds < 0:
            raise ValueError("ttl_seconds must be non-negative")
        self.ttl_seconds = ttl_seconds
        self._clock = clock
        self._entries: dict[str, tuple[RegistryStatus, float]] = {}

    def get(self, purl: str) -> RegistryStatus | None:
        """Return cached status if present and within TTL, evicting stale entries."""
        entry = self._entries.get(purl)
        if entry is None:
            return None
        status, checked_at = entry
        if (self._clock() - checked_at) > self.ttl_seconds:
            self._entries.pop(purl, None)
            return None
        return status

    def set(self, purl: str, status: RegistryStatus) -> None:
        """Cache definitive ``EXISTS`` or ``NOT_FOUND`` statuses; ignore transient errors."""
        if status not in (RegistryStatus.EXISTS, RegistryStatus.NOT_FOUND):
            return
        self._entries[purl] = (status, self._clock())


class SqliteRegistryCache:
    """SQLite-backed TTL cache for registry existence checks using parameterized SQL."""

    def __init__(
        self,
        db_path: Path,
        ttl_seconds: float = 86400.0,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Initialize a persistent SQLite TTL registry cache.

        Args:
            db_path: Filesystem path to the SQLite database file (parent dirs created).
            ttl_seconds: Non-negative TTL duration in seconds.
            clock: Clock callable returning epoch seconds.

        Raises:
            ValueError: If ``ttl_seconds`` is negative.
        """
        if ttl_seconds < 0:
            raise ValueError("ttl_seconds must be non-negative")
        self._db_path = db_path
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path)

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS registry_cache (
                        purl TEXT PRIMARY KEY,
                        status TEXT NOT NULL,
                        checked_at REAL NOT NULL
                    )
                    """
                )
        finally:
            conn.close()

    def get(self, purl: str) -> RegistryStatus | None:
        """Look up a cached status by PURL, evicting expired or corrupted rows safely."""
        conn = self._connect()
        try:
            # Parameterized query prevents SQL injection regardless of PURL contents.
            row = conn.execute(
                "SELECT status, checked_at FROM registry_cache WHERE purl = ?",
                (purl,),
            ).fetchone()
            if row is None:
                return None
            raw_status, checked_at = str(row[0]), float(row[1])
            if (self._clock() - checked_at) > self._ttl_seconds:
                with conn:
                    conn.execute("DELETE FROM registry_cache WHERE purl = ?", (purl,))
                return None
            try:
                return RegistryStatus(raw_status)
            except ValueError:
                # Fail safely and evict unrecognized status strings if DB was tampered/corrupted.
                with conn:
                    conn.execute("DELETE FROM registry_cache WHERE purl = ?", (purl,))
                return None
        finally:
            conn.close()

    def set(self, purl: str, status: RegistryStatus) -> None:
        """Upsert definitive ``EXISTS`` or ``NOT_FOUND`` results using parameterized SQL."""
        if status not in (RegistryStatus.EXISTS, RegistryStatus.NOT_FOUND):
            return
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO registry_cache (purl, status, checked_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(purl) DO UPDATE SET
                        status = excluded.status,
                        checked_at = excluded.checked_at
                    """,
                    (purl, status.value, self._clock()),
                )
        finally:
            conn.close()


class RegistryChecker(Protocol):
    """Protocol for checking whether a canonical PURL exists in its upstream registry."""

    def check(self, purl: str) -> RegistryStatus:
        """Check upstream registry existence for a canonical PURL.

        Args:
            purl: Canonical Package URL string.

        Returns:
            A :class:`RegistryStatus` indicating existence, absence, skip, or error.
        """


class HttpRegistryChecker:
    """HTTP-based package existence verifier for 8 upstream package registries."""

    def __init__(
        self,
        client: httpx.Client | None = None,
        cache: RegistryCache | None = None,
        timeout: float = 5.0,
    ) -> None:
        """Initialize the HTTP registry existence verifier.

        Args:
            client: Optional pre-configured ``httpx.Client`` (e.g., ``MockTransport`` in tests).
                When omitted, creates a hardened client with redirects disabled.
            cache: Optional :class:`RegistryCache` to avoid redundant network calls.
            timeout: Request timeout in seconds when creating a default client.
        """
        self._owns_client = client is None
        # Disable redirects by default to prevent open-redirect/SSRF pivot attacks.
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
        self._cache = cache

    @property
    def client(self) -> httpx.Client:
        """Return the underlying ``httpx.Client`` instance."""
        return self._client

    def close(self) -> None:
        """Close the internal HTTP client if owned by this instance."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> HttpRegistryChecker:
        """Enter context manager scope."""
        return self

    def __exit__(self, *_: object) -> None:
        """Close owned HTTP client resources on context manager exit."""
        self.close()

    def check(self, purl: str) -> RegistryStatus:
        """Check upstream registry existence for ``purl`` with optional TTL caching.

        Args:
            purl: Canonical Package URL string.

        Returns:
            ``EXISTS`` if confirmed, ``NOT_FOUND`` on 404/absent, ``SKIPPED`` for unsupported
            ecosystems or invalid coordinates, or ``ERROR`` on network/5xx failures.
        """
        if (
            _has_control_chars(purl)
            or len(purl) > MAX_PACKAGE_INPUT_LENGTH
            or "?" in purl
            or "#" in purl
        ):
            return RegistryStatus.SKIPPED

        if self._cache is not None:
            cached = self._cache.get(purl)
            if cached is not None:
                return cached

        try:
            parsed = PackageURL.from_string(purl)
        except ValueError:
            return RegistryStatus.SKIPPED

        status = self._query_registry(parsed)
        if self._cache is not None and status in (
            RegistryStatus.EXISTS,
            RegistryStatus.NOT_FOUND,
        ):
            self._cache.set(purl, status)
        return status

    def _query_registry(self, parsed: PackageURL) -> RegistryStatus:
        """Dispatch a coordinate-validated HTTP metadata query to the ecosystem registry."""
        try:
            if parsed.type == "pypi":
                if not _validate_coordinate_safety(parsed.name) or not _PYPI_NAME_RE.match(
                    parsed.name
                ):
                    return RegistryStatus.SKIPPED
                url = f"https://pypi.org/pypi/{quote(parsed.name, safe='')}/json"
                resp = self._client.get(url)
                return self._status_from_http_code(resp.status_code)

            if parsed.type == "npm":
                if not _validate_coordinate_safety(parsed.name) or not _NPM_NAME_RE.match(
                    parsed.name
                ):
                    return RegistryStatus.SKIPPED
                if parsed.namespace is not None:
                    if not _validate_coordinate_safety(parsed.namespace) or not _NPM_SCOPE_RE.match(
                        parsed.namespace
                    ):
                        return RegistryStatus.SKIPPED
                    pkg_path = f"{parsed.namespace}/{parsed.name}"
                else:
                    pkg_path = parsed.name
                encoded = quote(pkg_path, safe="@")
                url = f"https://registry.npmjs.org/{encoded}"
                resp = self._client.get(url)
                return self._status_from_http_code(resp.status_code)

            if parsed.type == "maven":
                if not parsed.namespace:
                    return RegistryStatus.SKIPPED
                # Enforce strict Maven coordinate allowlist to prevent Solr query syntax injection.
                if (
                    not _validate_coordinate_safety(parsed.namespace)
                    or not _validate_coordinate_safety(parsed.name)
                    or not _MAVEN_COORD_RE.match(parsed.namespace)
                    or not _MAVEN_COORD_RE.match(parsed.name)
                ):
                    return RegistryStatus.SKIPPED
                resp = self._client.get(
                    "https://search.maven.org/solrsearch/select",
                    params={
                        "q": f'g:"{parsed.namespace}" AND a:"{parsed.name}"',
                        "rows": "1",
                        "wt": "json",
                    },
                )
                if resp.status_code == 404:
                    return RegistryStatus.NOT_FOUND
                if resp.status_code >= 500 or resp.status_code != 200:
                    return RegistryStatus.ERROR
                payload = resp.json()
                num_found = int(payload.get("response", {}).get("numFound", 0))
                return RegistryStatus.EXISTS if num_found > 0 else RegistryStatus.NOT_FOUND

            if parsed.type == "golang":
                if not parsed.namespace:
                    return RegistryStatus.SKIPPED
                if not _validate_coordinate_safety(
                    parsed.namespace
                ) or not _validate_coordinate_safety(parsed.name):
                    return RegistryStatus.SKIPPED
                module_path = f"{parsed.namespace}/{parsed.name}"
                segments = module_path.split("/")
                if any(seg in {"", ".", ".."} or not _GO_SEGMENT_RE.match(seg) for seg in segments):
                    return RegistryStatus.SKIPPED
                escaped = _escape_go_module(module_path)
                encoded_path = "/".join(quote(seg, safe="!") for seg in escaped.split("/"))
                url = f"https://proxy.golang.org/{encoded_path}/@v/list"
                resp = self._client.get(url)
                if resp.status_code in (404, 410):
                    return RegistryStatus.NOT_FOUND
                return self._status_from_http_code(resp.status_code)

            if parsed.type == "cargo":
                if not _validate_coordinate_safety(parsed.name) or not _CARGO_NAME_RE.match(
                    parsed.name
                ):
                    return RegistryStatus.SKIPPED
                url = f"https://crates.io/api/v1/crates/{quote(parsed.name, safe='')}"
                resp = self._client.get(url)
                return self._status_from_http_code(resp.status_code)

            if parsed.type == "gem":
                if not _validate_coordinate_safety(parsed.name) or not _GEM_NAME_RE.match(
                    parsed.name
                ):
                    return RegistryStatus.SKIPPED
                url = f"https://rubygems.org/api/v1/gems/{quote(parsed.name, safe='')}.json"
                resp = self._client.get(url)
                return self._status_from_http_code(resp.status_code)

            if parsed.type == "nuget":
                lowered_name = parsed.name.lower()
                if not _validate_coordinate_safety(parsed.name) or not _NUGET_NAME_RE.match(
                    parsed.name
                ):
                    return RegistryStatus.SKIPPED
                encoded_name = quote(lowered_name, safe="")
                url = f"https://api.nuget.org/v3-flatcontainer/{encoded_name}/index.json"
                resp = self._client.get(url)
                return self._status_from_http_code(resp.status_code)

            if parsed.type == "composer":
                if not parsed.namespace:
                    return RegistryStatus.SKIPPED
                lowered_ns = parsed.namespace.lower()
                lowered_name = parsed.name.lower()
                if (
                    not _validate_coordinate_safety(lowered_ns)
                    or not _validate_coordinate_safety(lowered_name)
                    or not _COMPOSER_PART_RE.match(lowered_ns)
                    or not _COMPOSER_PART_RE.match(lowered_name)
                ):
                    return RegistryStatus.SKIPPED
                url = (
                    f"https://repo.packagist.org/p2/{quote(lowered_ns, safe='')}/"
                    f"{quote(lowered_name, safe='')}.json"
                )
                resp = self._client.get(url)
                return self._status_from_http_code(resp.status_code)

            return RegistryStatus.SKIPPED
        except (httpx.HTTPError, ValueError, TypeError):
            return RegistryStatus.ERROR

    @staticmethod
    def _status_from_http_code(status_code: int) -> RegistryStatus:
        """Map standard HTTP status codes to tri-state registry results."""
        if status_code == 200:
            return RegistryStatus.EXISTS
        if status_code == 404:
            return RegistryStatus.NOT_FOUND
        return RegistryStatus.ERROR


def _split_namespace_and_name(
    purl_type: str,
    cleaned_name: str,
    explicit_namespace: str | None,
    osv_ecosystem: str | None,
) -> tuple[str | None, str, bool]:
    """Normalize package namespace and name for a canonical PURL type.

    Returns ``(namespace, name, namespace_is_distro)``.
    """
    ns = explicit_namespace.strip() if explicit_namespace else None
    name = cleaned_name.strip()

    if purl_type == "pypi":
        return None, _normalize_pep503(name), False

    if purl_type == "npm":
        if name.startswith("@") and "/" in name:
            scope, pkg = name.split("/", 1)
            return scope.lower(), pkg.lower(), False
        if ns:
            normalized_scope = f"@{ns.lstrip('@').lower()}"
            return normalized_scope, name.lower(), False
        return None, name.lower(), False

    if purl_type == "maven":
        if ":" in name:
            group, artifact = name.split(":", 1)
            return group.strip(), artifact.strip(), False
        if "/" in name:
            group, artifact = name.split("/", 1)
            return group.strip(), artifact.strip(), False
        # Drop bogus ecosystem-echo namespaces (e.g. LLM returning namespace="maven").
        maven_ns = None if (ns is not None and ns.lower() in {"maven", "java"}) else ns
        return maven_ns, name, False

    if purl_type == "golang":
        if "/" in name:
            module_ns, pkg_leaf = name.rsplit("/", 1)
            full_ns = module_ns.strip()
            if ns and not full_ns.lower().startswith(ns.lower()):
                full_ns = f"{ns}/{full_ns}"
            return full_ns, pkg_leaf.strip(), False
        return ns, name, False

    if purl_type in _DISTRO_PURL_TYPES:
        distro_ns = ns.lower() if ns else _default_distro_namespace(purl_type, osv_ecosystem)
        return distro_ns, name.lower(), True

    if purl_type == "composer":
        if "/" in name:
            vendor, pkg = name.split("/", 1)
            return vendor.lower(), pkg.lower(), False
        return (ns.lower() if ns else None), name.lower(), False

    if purl_type == "github":
        if "/" in name:
            owner, repo = name.split("/", 1)
            return owner.lower(), repo.lower(), False
        return (ns.lower() if ns else None), name.lower(), False

    # Flat PURL registries (cargo, gem, nuget) never carry namespaces in canonical PURLs.
    if purl_type in {"cargo", "gem"}:
        return None, name.lower(), False

    if purl_type == "nuget":
        return None, name, False

    if purl_type == "generic":
        generic_ns = ns.lower() if ns else None
        if generic_ns in {"generic", "runtime"}:
            generic_ns = None
        return generic_ns, name.lower(), False

    return ns, name, False


def _build_canonical_purl(purl_type: str, namespace: str | None, name: str) -> str:
    """Construct a canonical Package URL string without version, qualifiers, or subpath."""
    purl = PackageURL(type=purl_type, namespace=namespace, name=name)
    return str(purl.to_string())


@overload
def resolve_purl(
    target: ExtractedPackageClaim,
    ecosystem: str | None = None,
    namespace: str | None = None,
    *,
    registry_checker: RegistryChecker | None = None,
) -> PurlResolutionResult: ...


@overload
def resolve_purl(
    target: str,
    ecosystem: str | None = None,
    namespace: str | None = None,
    *,
    registry_checker: RegistryChecker | None = None,
) -> PurlResolutionResult: ...


def resolve_purl(
    target: ExtractedPackageClaim | str,
    ecosystem: str | None = None,
    namespace: str | None = None,
    *,
    registry_checker: RegistryChecker | None = None,
) -> PurlResolutionResult:
    """Resolve a raw package claim or fuzzy name to a canonical PURL.

    Applies ecosystem normalization, generic-name blocking (without allowing OS distro defaults
    to bypass the blocklist), strict traversal/injection coordinate validation, and optional
    upstream registry existence checking.

    Args:
        target: Either an :class:`ExtractedPackageClaim` or a raw package/PURL string.
        ecosystem: Optional ecosystem hint overriding ``target.ecosystem``.
        namespace: Optional namespace/scope/groupId overriding ``target.namespace``.
        registry_checker: Optional :class:`RegistryChecker` (defaults to offline ``None``).

    Returns:
        A :class:`PurlResolutionResult` with canonical PURL, validity flags, and diagnostics.
    """
    if isinstance(target, ExtractedPackageClaim):
        raw_name = target.raw_package_name
        eco_input = ecosystem if ecosystem is not None else target.ecosystem
        ns_input = namespace if namespace is not None else target.namespace
    else:
        raw_name = target
        eco_input = ecosystem
        ns_input = namespace

    if _has_control_chars(raw_name) or (ns_input is not None and _has_control_chars(ns_input)):
        return PurlResolutionResult(
            canonical_purl=None,
            ecosystem=None,
            osv_ecosystem=None,
            is_valid=False,
            reasons=("Package identifier or namespace contains control characters.",),
        )

    stripped_raw = raw_name.strip()
    if not stripped_raw:
        return PurlResolutionResult(
            canonical_purl=None,
            ecosystem=None,
            osv_ecosystem=None,
            is_valid=False,
            reasons=("Package name is empty.",),
        )

    if len(stripped_raw) > MAX_PACKAGE_INPUT_LENGTH or (
        ns_input is not None and len(ns_input) > MAX_PACKAGE_INPUT_LENGTH
    ):
        return PurlResolutionResult(
            canonical_purl=None,
            ecosystem=None,
            osv_ecosystem=None,
            is_valid=False,
            reasons=(f"Package input exceeds {MAX_PACKAGE_INPUT_LENGTH} characters.",),
        )

    # Path A: Input is already formatted as a Package URL (pkg:...).
    if stripped_raw.startswith("pkg:"):
        try:
            parsed = PackageURL.from_string(stripped_raw)
        except ValueError as exc:
            return PurlResolutionResult(
                canonical_purl=None,
                ecosystem=None,
                osv_ecosystem=None,
                is_valid=False,
                reasons=(f"Malformed PURL '{stripped_raw}': {exc}",),
            )
        purl_type, hinted_osv = normalize_ecosystem(parsed.type)
        if purl_type is None:
            return PurlResolutionResult(
                canonical_purl=None,
                ecosystem=parsed.type,
                osv_ecosystem=None,
                is_valid=False,
                reasons=(f"Unsupported PURL ecosystem '{parsed.type}'.",),
            )
        ns_hint = parsed.namespace or ns_input
        osv_ecosystem = _resolve_osv_ecosystem(purl_type, ns_hint, hinted_osv)
        norm_ns, norm_name, ns_is_distro = _split_namespace_and_name(
            purl_type=purl_type,
            cleaned_name=parsed.name,
            explicit_namespace=ns_hint,
            osv_ecosystem=osv_ecosystem,
        )
    else:
        # Path B: Fuzzy / natural-language package name + optional ecosystem hint.
        cleaned_name, inferred_eco = _strip_natural_language(stripped_raw)
        purl_type, hinted_osv = normalize_ecosystem(eco_input or inferred_eco)
        if purl_type == "generic" and (
            cleaned_name.lower().startswith("golang.org/")
            or (ns_input or "").strip().lower().startswith("golang.org/")
        ):
            purl_type, hinted_osv = ("golang", "Go")
        if purl_type is None:
            return PurlResolutionResult(
                canonical_purl=None,
                ecosystem=eco_input or inferred_eco,
                osv_ecosystem=None,
                is_valid=False,
                reasons=("Could not determine canonical ecosystem for package claim.",),
            )
        osv_ecosystem = _resolve_osv_ecosystem(purl_type, ns_input, hinted_osv)
        norm_ns, norm_name, ns_is_distro = _split_namespace_and_name(
            purl_type=purl_type,
            cleaned_name=cleaned_name,
            explicit_namespace=ns_input,
            osv_ecosystem=osv_ecosystem,
        )

    distro_ns_invalid = (
        purl_type in _DISTRO_PURL_TYPES
        and norm_ns is not None
        and (not _DISTRO_NAMESPACE_RE.match(norm_ns) or norm_ns in _NON_DISTRO_NAMESPACE_BLOCKLIST)
    )
    if (
        distro_ns_invalid
        or not _validate_coordinate_safety(norm_name)
        or (norm_ns is not None and not _validate_coordinate_safety(norm_ns))
    ):
        return PurlResolutionResult(
            canonical_purl=None,
            ecosystem=purl_type,
            osv_ecosystem=osv_ecosystem,
            namespace=norm_ns,
            name=norm_name or None,
            is_valid=False,
            reasons=(
                f"Rejected unsafe or malformed package coordinates (ns={norm_ns!r}, "
                f"name={norm_name!r}).",
            ),
        )

    # Auto-assigned OS distro namespaces and pkg:generic/ namespaces must not bypass
    # always-generic blocklist words such as 'utils' or 'core'. Runtime names ('kernel',
    # 'ruby') are blocked on package registries but permitted on OS/generic ecosystems.
    has_explicit_package_ns = norm_ns is not None and not ns_is_distro and purl_type != "generic"
    is_single_char = len(norm_name) <= 1
    lowered_name = norm_name.lower()
    is_always_generic = lowered_name in GENERIC_PACKAGE_BLOCKLIST
    is_registry_only_generic = (
        lowered_name in REGISTRY_ONLY_GENERIC_BLOCKLIST
        and purl_type not in _RUNTIME_FRIENDLY_PURL_TYPES
    )

    if is_single_char or (
        (is_always_generic or is_registry_only_generic) and not has_explicit_package_ns
    ):
        return PurlResolutionResult(
            canonical_purl=None,
            ecosystem=purl_type,
            osv_ecosystem=osv_ecosystem,
            namespace=norm_ns,
            name=norm_name,
            is_valid=False,
            is_blocked_generic=True,
            reasons=(
                f"Blocked overly generic or single-character package name '{norm_name}' "
                f"for ecosystem '{purl_type}' without an explicit package namespace.",
            ),
        )

    try:
        canonical_purl = _build_canonical_purl(purl_type, norm_ns, norm_name)
    except ValueError as exc:
        return PurlResolutionResult(
            canonical_purl=None,
            ecosystem=purl_type,
            osv_ecosystem=osv_ecosystem,
            namespace=norm_ns,
            name=norm_name,
            is_valid=False,
            reasons=(f"Failed to construct canonical PURL: {exc}",),
        )

    registry_status = RegistryStatus.SKIPPED
    reasons: list[str] = []
    is_valid = True

    if registry_checker is not None:
        registry_status = registry_checker.check(canonical_purl)
        if registry_status == RegistryStatus.NOT_FOUND:
            is_valid = False
            reasons.append(f"Package '{canonical_purl}' was not found in upstream registry (404).")
        elif registry_status == RegistryStatus.ERROR:
            reasons.append(
                f"Upstream registry lookup errored for '{canonical_purl}'; "
                "continuing without rejecting."
            )

    return PurlResolutionResult(
        canonical_purl=canonical_purl,
        ecosystem=purl_type,
        osv_ecosystem=osv_ecosystem,
        namespace=norm_ns,
        name=norm_name,
        is_valid=is_valid,
        is_blocked_generic=False,
        registry_status=registry_status,
        reasons=tuple(reasons),
    )
