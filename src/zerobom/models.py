"""Canonical strict Pydantic v2 data contracts for zerobom.

All models in this module inherit from :class:`StrictModel`, which enforces:

- ``strict=True``: rejects implicit type coercion across module boundaries.
- ``extra="forbid"``: fails closed on unexpected or prompt-injected fields.
- ``frozen=True``: guarantees immutability once constructed.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Restrict accepted URI schemes to prevent dangerous schemes (e.g., javascript:, data:).
ALLOWED_URI_SCHEMES: frozenset[str] = frozenset({"http", "https", "offline", "file"})
ALLOWED_HTTP_SCHEMES: frozenset[str] = frozenset({"http", "https"})
MAX_URI_LENGTH = 2048
MAX_ASSET_METADATA_ENTRIES = 32
MAX_ASSET_METADATA_KEY_LENGTH = 64
MAX_ASSET_METADATA_VALUE_LENGTH = 512
MAX_SUPPORTING_QUOTES = 5
_SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_DISTRO_RELEASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")


def _has_control_chars(value: str) -> bool:
    """Return True if value contains C0 or DEL/C1 control chars (including ANSI ESC/CRLF/NUL)."""
    return any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in value)


def _require_safe_text(value: str, field_name: str) -> str:
    """Validate that a string has no control characters and is non-empty after stripping."""
    if _has_control_chars(value):
        raise ValueError(f"{field_name} must not contain control characters")
    return _require_non_empty_str(value, field_name)


def _require_non_empty_str(value: str, field_name: str) -> str:
    """Validate that a string is non-empty after stripping surrounding whitespace.

    Args:
        value: Untrusted input string.
        field_name: Name of the validated field for diagnostic messages.

    Returns:
        The trimmed non-empty string.

    Raises:
        ValueError: If ``value`` is empty or whitespace-only.
    """
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{field_name} must not be empty or whitespace-only")
    return stripped


def _require_uri(
    value: str,
    field_name: str,
    *,
    allowed_schemes: frozenset[str] = ALLOWED_URI_SCHEMES,
) -> str:
    """Validate that a string is a safe, bounded URI within the allowed scheme set.

    Args:
        value: Untrusted URI candidate string.
        field_name: Name of the validated field for diagnostic messages.
        allowed_schemes: Explicit set of permitted lowercase URI schemes.

    Returns:
        Normalized URI string with surrounding spaces trimmed.

    Raises:
        ValueError: If the URI contains control characters or whitespace, exceeds
            ``MAX_URI_LENGTH``, uses a disallowed scheme, or lacks a valid authority/path.
    """
    # Check control chars before stripping so trailing CR/LF/NUL are never silently dropped.
    if _has_control_chars(value):
        raise ValueError(f"{field_name} must not contain control characters")

    stripped = _require_non_empty_str(value, field_name)
    if len(stripped) > MAX_URI_LENGTH:
        raise ValueError(f"{field_name} exceeds maximum URI length of {MAX_URI_LENGTH} chars")
    if any(ch.isspace() for ch in stripped):
        raise ValueError(f"{field_name} must not contain whitespace")

    parsed = urlparse(stripped)
    scheme = parsed.scheme.lower()
    if "://" not in stripped or scheme not in allowed_schemes:
        allowed = ", ".join(sorted(allowed_schemes))
        raise ValueError(f"{field_name} must use an allowed URI scheme ({allowed})")

    if scheme in {"http", "https"}:
        if not parsed.netloc:
            raise ValueError(f"{field_name} with scheme '{scheme}' must include a host")
    elif not parsed.netloc and not parsed.path:
        raise ValueError(f"{field_name} must include a valid host or path")

    return stripped


def _format_rfc3339_utc(dt: datetime) -> str:
    """Format a datetime as an RFC 3339 UTC timestamp string ending in ``'Z'``.

    Args:
        dt: Aware or naive datetime instance (naive timestamps are treated as UTC).

    Returns:
        Timestamp formatted as ``YYYY-MM-DDTHH:MM:SSZ``.
    """
    utc_dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class StrictModel(BaseModel):
    """Base model enforcing strict validation, immutability, and no extra fields."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class SourceTier(StrEnum):
    """Credibility tier assigned to a security advisory source."""

    TIER_1 = "tier_1"
    TIER_2 = "tier_2"
    UNKNOWN = "unknown"


class ArticleType(StrEnum):
    """Classification of a fetched article's disclosure role prior to routing."""

    ORIGINAL_DISCLOSURE = "original_disclosure"
    VENDOR_ADVISORY = "vendor_advisory"
    MALICIOUS_PACKAGE = "malicious_package"
    KNOWN_VULN_ANALYSIS = "known_vuln_analysis"
    RESEARCH_GUIDANCE = "research_guidance"
    PRODUCT_ANNOUNCEMENT = "product_announcement"
    BENCHMARK_EVALUATION = "benchmark_evaluation"
    OFFENSIVE_TECHNIQUE = "offensive_technique"
    NON_VULNERABILITY = "non_vulnerability"


class FeedKind(StrEnum):
    """Discovery format configured for an allowlisted source endpoint."""

    RSS = "rss"
    SITEMAP = "sitemap"
    HTML_INDEX = "html_index"
    AUTO = "auto"


class GroundingStatus(StrEnum):
    """Outcome of two-stage verbatim quote grounding."""

    VERIFIED = "verified"
    QUOTE_ONLY_WEAK = "quote_only_weak"
    UNGROUNDED = "ungrounded"


class GroundingMatchType(StrEnum):
    """How the evidence quote matched the raw article body."""

    EXACT = "exact"
    NORMALIZED = "normalized"
    NONE = "none"


class RegistryStatus(StrEnum):
    """Result of checking package existence against an upstream registry."""

    EXISTS = "exists"
    NOT_FOUND = "not_found"
    SKIPPED = "skipped"
    ERROR = "error"


class RoutingDecision(StrEnum):
    """Credibility routing outcome based on the two-axis composite score."""

    AUTO = "auto"
    TRIAGE = "triage"
    DROP = "drop"


class VulnerabilitySeverity(StrEnum):
    """Normalized qualitative vulnerability severity."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class RawArticle(StrictModel):
    """Normalized ingested security blog article prior to extraction and verification.

    Attributes:
        url: Canonical source URI of the ingested article.
        title: Non-empty article headline.
        body: Cleaned plain-text article body used for verbatim quote grounding.
        source_name: Human-readable publisher name (e.g., ``"Project Zero"``).
        source_tier: Credibility tier weight category of the publisher.
        published_at: Publication timestamp.
        published_at_inferred: True when ``published_at`` fell back to fetch time rather than an
            explicit feed or HTML metadata date.
        fetched_at: Optional retrieval timestamp.
        author: Optional author attribution.
    """

    url: str
    title: str
    body: str
    source_name: str
    source_tier: SourceTier = SourceTier.UNKNOWN
    published_at: datetime
    published_at_inferred: bool = False
    fetched_at: datetime | None = None
    author: str | None = None

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        return _require_uri(value, "url")

    @field_validator("title", "source_name")
    @classmethod
    def _validate_non_empty_fields(cls, value: str, info: Any) -> str:
        return _require_safe_text(value, str(info.field_name))


class VersionConstraint(StrictModel):
    """Structured raw affected version bounds prior to deterministic compilation.

    Attributes:
        introduced: Inclusive lower bound (or ``"0"`` when unknown/since origin).
        fixed: Exclusive upper bound representing the first patched version.
        last_affected: Inclusive upper bound representing the last vulnerable version.
        exact: Single vulnerable version string (mutually exclusive with range bounds).
        raw_specifier: Raw range expression (e.g., ``">= 1.2.0, < 1.5.4"``).
        is_unbounded: Whether all versions from ``introduced`` onward are claimed vulnerable.
    """

    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    exact: str | None = None
    raw_specifier: str | None = None
    is_unbounded: bool = False

    @model_validator(mode="after")
    def _validate_bounds(self) -> VersionConstraint:
        """Enforce internal consistency of extracted version boundary fields."""
        string_fields = (
            ("introduced", self.introduced),
            ("fixed", self.fixed),
            ("last_affected", self.last_affected),
            ("exact", self.exact),
            ("raw_specifier", self.raw_specifier),
        )
        for name, val in string_fields:
            if val is not None and not val.strip():
                raise ValueError(f"{name} must not be empty or whitespace-only when provided")

        has_any = (
            self.introduced is not None
            or self.fixed is not None
            or self.last_affected is not None
            or self.exact is not None
            or self.raw_specifier is not None
            or self.is_unbounded
        )
        if not has_any:
            raise ValueError(
                "VersionConstraint must specify at least one of introduced, fixed, "
                "last_affected, exact, raw_specifier, or is_unbounded=True"
            )

        if self.fixed is not None and self.last_affected is not None:
            raise ValueError("fixed and last_affected cannot both be set on one VersionConstraint")

        if self.exact is not None and (
            self.introduced is not None
            or self.fixed is not None
            or self.last_affected is not None
            or self.is_unbounded
        ):
            raise ValueError(
                "exact cannot be combined with introduced, fixed, last_affected, or is_unbounded"
            )

        if self.is_unbounded and (
            self.fixed is not None or self.last_affected is not None or self.exact is not None
        ):
            raise ValueError(
                "is_unbounded=True cannot be combined with fixed, last_affected, or exact"
            )

        return self


class ExtractedPackageClaim(StrictModel):
    """Single affected package claim produced by an upstream extractor.

    Attributes:
        raw_package_name: Unnormalized package identifier or PURL string.
        ecosystem: Optional ecosystem hint (e.g., ``"pypi"``, ``"npm"``, ``"Maven"``).
        namespace: Optional package namespace/scope/groupId.
        distro_release: Optional OS distro release or stream qualifier (e.g., ``"8"``, ``"9"``).
        version_constraints: Tuple of extracted version constraints.
        evidence_quote: Verbatim supporting quote copied from the source article.
        supporting_quotes: Optional additional verbatim quotes for multi-update advisories.
        claim_aliases: Optional per-claim advisory aliases (e.g., CVE/GHSA IDs for multi-flaw
            posts).
        fix_commit_url: Optional validated URI to a fix commit or PR.
        poc_url: Optional validated URI to a proof-of-concept or exploit writeup.
    """

    raw_package_name: str
    ecosystem: str | None = None
    namespace: str | None = None
    distro_release: str | None = None
    version_constraints: tuple[VersionConstraint, ...] = ()
    evidence_quote: str
    supporting_quotes: tuple[str, ...] = ()
    claim_aliases: tuple[str, ...] = ()
    fix_commit_url: str | None = None
    poc_url: str | None = None

    @field_validator("raw_package_name")
    @classmethod
    def _validate_raw_package_name(cls, value: str) -> str:
        return _require_non_empty_str(value, "raw_package_name")

    @field_validator("distro_release")
    @classmethod
    def _validate_distro_release(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if _has_control_chars(value):
            raise ValueError("distro_release must not contain control characters")
        cleaned = value.strip()
        if not cleaned or ".." in cleaned or not _DISTRO_RELEASE_RE.match(cleaned):
            raise ValueError(
                "distro_release must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$ without '..'"
            )
        return cleaned

    @field_validator("supporting_quotes")
    @classmethod
    def _validate_supporting_quotes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_SUPPORTING_QUOTES:
            raise ValueError(f"supporting_quotes cannot exceed {MAX_SUPPORTING_QUOTES} entries")
        cleaned: list[str] = []
        for quote in value:
            if any((ord(ch) < 32 and ch not in "\t\n\r") or ord(ch) == 127 for ch in quote):
                raise ValueError("supporting_quotes must not contain ASCII control characters")
            if not quote.strip():
                raise ValueError("supporting_quotes entries must not be empty or whitespace-only")
            cleaned.append(quote)
        return tuple(cleaned)

    @field_validator("claim_aliases")
    @classmethod
    def _validate_claim_aliases(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_require_safe_text(alias, "claim_aliases") for alias in value)

    @field_validator("fix_commit_url", "poc_url")
    @classmethod
    def _validate_optional_urls(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        return _require_uri(value, str(info.field_name))


class ExtractedAdvisory(StrictModel):
    """Structured advisory candidate extracted from a :class:`RawArticle`.

    Attributes:
        article_url: Canonical URI of the source article.
        title: Non-empty advisory title.
        summary: Concise vulnerability summary.
        details: Extended technical writeup.
        article_type: Optional disclosure-role classification emitted by the extractor.
        claims: Zero or more package vulnerability claims (empty for non-vuln posts).
        severity: Qualitative severity rating.
        cwe_ids: Associated CWE identifiers.
        references: Additional validated external reference URIs.
        known_aliases: Optional CVE/GHSA aliases if mentioned.
        published_at: Optional publication timestamp override.
        prompt_version: Optional version tag of the extraction prompt used.
        extractor_model: Optional LLM identifier that produced the candidate advisory.
    """

    article_url: str
    title: str
    summary: str
    details: str = ""
    article_type: ArticleType | None = None
    claims: tuple[ExtractedPackageClaim, ...] = ()
    severity: VulnerabilitySeverity = VulnerabilitySeverity.UNKNOWN
    cwe_ids: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    known_aliases: tuple[str, ...] = ()
    published_at: datetime | None = None
    prompt_version: str | None = None
    extractor_model: str | None = None

    @field_validator("article_url")
    @classmethod
    def _validate_article_url(cls, value: str) -> str:
        return _require_uri(value, "article_url")

    @field_validator("title")
    @classmethod
    def _validate_title(cls, value: str) -> str:
        return _require_non_empty_str(value, "title")

    @field_validator("references")
    @classmethod
    def _validate_references(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_require_uri(val, "references") for val in values)


def _url_origin(uri: str) -> tuple[str, str, int]:
    """Return canonical ``(scheme, lowercase_host, effective_port)`` for an HTTP/HTTPS URI."""
    parsed = urlparse(uri)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
    return (scheme, host, port)


class SourceFeedConfig(StrictModel):
    """Configuration entry for an allowlisted security blog discovery source.

    Attributes:
        name: Human-readable publisher name.
        url: HTTP/HTTPS feed, sitemap, or blog index URL.
        tier: Source credibility tier assigned to articles from this feed.
        kind: Discovery format (``rss``, ``sitemap``, ``html_index``, or ``auto``).
        url_prefix: Optional same-origin URL prefix used to filter sitemap or HTML index links.
        enabled: Whether the feed is active during polling.
        tags: Optional descriptive tags for filtering/reporting.
    """

    name: str
    url: str
    tier: SourceTier = SourceTier.TIER_2
    kind: FeedKind = FeedKind.RSS
    url_prefix: str | None = None
    enabled: bool = True
    tags: tuple[str, ...] = ()

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        return _require_safe_text(value, "name")

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        return _require_uri(value, "url", allowed_schemes=ALLOWED_HTTP_SCHEMES)

    @field_validator("url_prefix")
    @classmethod
    def _validate_url_prefix(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _require_uri(value, "url_prefix", allowed_schemes=ALLOWED_HTTP_SCHEMES)

    @model_validator(mode="after")
    def _validate_kind_and_prefix(self) -> SourceFeedConfig:
        if self.kind == FeedKind.HTML_INDEX:
            if self.url_prefix is None:
                raise ValueError("html_index feeds require an explicit same-origin url_prefix")
            if _url_origin(self.url_prefix) != _url_origin(self.url):
                raise ValueError(
                    "url_prefix must share the exact same origin as url for html_index feeds"
                )
        return self


class SourcesConfig(StrictModel):
    """Top-level configuration parsed from ``sources.yaml``.

    Attributes:
        version: Schema version integer (must be >= 1).
        feeds: Configured RSS/Atom source feeds.
    """

    version: int = Field(default=1, ge=1)
    feeds: tuple[SourceFeedConfig, ...] = ()


class FeedEntry(StrictModel):
    """Single item discovered from an RSS or Atom feed.

    Attributes:
        url: HTTP/HTTPS URL of the linked blog post.
        title: Post title.
        summary: Feed-level snippet/summary text.
        published_at: Publication timestamp.
        published_at_inferred: True when the feed/index lacked a timestamp and fell back to now.
        source_name: Name of the parent feed.
        source_tier: Credibility tier inherited from the parent feed.
    """

    url: str
    title: str
    summary: str = ""
    published_at: datetime
    published_at_inferred: bool = False
    source_name: str
    source_tier: SourceTier = SourceTier.UNKNOWN

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        return _require_uri(value, "url", allowed_schemes=ALLOWED_HTTP_SCHEMES)

    @field_validator("title", "source_name")
    @classmethod
    def _validate_non_empty(cls, value: str, info: Any) -> str:
        return _require_safe_text(value, str(info.field_name))


class PrefilterResult(StrictModel):
    """Output of deterministic keyword/regex filtering prior to LLM extraction.

    Attributes:
        passed: True when the article warrants LLM extraction.
        score: Heuristic relevance score in ``[0.0, 1.0]``.
        vuln_signals: Matched vulnerability indicator tags.
        software_signals: Matched package/version/ecosystem indicator tags.
        marketing_signals: Matched promotional/non-vulnerability indicator tags.
        extracted_aliases: Reserved CVE/GHSA identifiers extracted deterministically.
        reasons: Diagnostic messages explaining pass/drop rationale.
    """

    passed: bool
    score: float = Field(ge=0.0, le=1.0)
    vuln_signals: tuple[str, ...] = ()
    software_signals: tuple[str, ...] = ()
    marketing_signals: tuple[str, ...] = ()
    extracted_aliases: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()


class ArticleStateRecord(StrictModel):
    """Persisted ingestion and processing state for a canonical article URL.

    Attributes:
        canonical_url: Canonicalized article URI used as primary key.
        content_sha256: Lowercase 64-character SHA-256 hex digest of normalized body text.
        etag: Optional HTTP ``ETag`` header from the last fetch.
        last_modified: Optional HTTP ``Last-Modified`` header from the last fetch.
        last_seen_at: Timestamp when the article was last processed.
        advisory_id: Compiled ``PRECVE`` advisory ID if produced.
        routing: Last verification routing decision if evaluated.
    """

    canonical_url: str
    content_sha256: str
    etag: str | None = None
    last_modified: str | None = None
    last_seen_at: datetime
    advisory_id: str | None = None
    routing: RoutingDecision | None = None

    @field_validator("canonical_url")
    @classmethod
    def _validate_canonical_url(cls, value: str) -> str:
        return _require_uri(value, "canonical_url")

    @field_validator("content_sha256")
    @classmethod
    def _validate_sha256(cls, value: str) -> str:
        stripped = value.strip()
        if not _SHA256_HEX_RE.match(stripped):
            raise ValueError("content_sha256 must be a 64-character hexadecimal SHA-256 digest")
        return stripped.lower()


class GroundingResult(StrictModel):
    """Verification output of two-stage verbatim quote grounding.

    Attributes:
        status: Overall grounding verdict (``VERIFIED``, ``QUOTE_ONLY_WEAK``, or ``UNGROUNDED``).
        match_type: Whether Stage 1 matched verbatim or via Unicode/whitespace normalization.
        quote_found_in_article: True if the quote matched inside the article body.
        package_token_found: True if a normalized package identifier appeared inside the quote.
        version_tokens_found: True if a claimed version token appeared inside the quote (or none
            were claimed).
        matched_span: Optional ``(start, end)`` slice offsets within exact or normalized body.
        reasons: Diagnostic messages explaining any grounding degradation or failure.
    """

    status: GroundingStatus
    match_type: GroundingMatchType
    quote_found_in_article: bool
    package_token_found: bool
    version_tokens_found: bool
    matched_span: tuple[int, int] | None = None
    reasons: tuple[str, ...] = ()


class PurlResolutionResult(StrictModel):
    """Deterministic canonical Package URL resolution and optional registry check output.

    Attributes:
        canonical_purl: Canonical Package URL string, or ``None`` if resolution failed.
        ecosystem: Canonical PURL ecosystem type (e.g., ``"pypi"``, ``"deb"``).
        osv_ecosystem: Canonical OSV ecosystem name (e.g., ``"PyPI"``, ``"Debian"``).
        namespace: Resolved package namespace/scope/groupId, if any.
        name: Normalized package name.
        is_valid: True when resolution succeeded, name is non-generic, and not 404 in registry.
        is_blocked_generic: True if rejected by the generic-name blocklist.
        registry_status: Upstream registry existence verification outcome.
        reasons: Diagnostic explanations for failures or non-fatal registry errors.
    """

    canonical_purl: str | None
    ecosystem: str | None
    osv_ecosystem: str | None
    namespace: str | None = None
    name: str | None = None
    is_valid: bool
    is_blocked_generic: bool = False
    registry_status: RegistryStatus = RegistryStatus.SKIPPED
    reasons: tuple[str, ...] = ()


class ClaimVerificationResult(StrictModel):
    """Per-claim verification and two-axis credibility scoring outcome.

    Attributes:
        claim: Original extracted claim being evaluated.
        grounding: Two-stage verbatim quote grounding outcome.
        purl: Canonical PURL resolution and registry verification outcome.
        has_valid_version_range: True if all version constraints parsed cleanly.
        has_bounded_version_range: True if at least one valid bounded/exact range was present.
        extraction_specificity: Normalized extraction quality score in ``[0.0, 1.0]``.
        composite_score: Two-axis ``source_tier_weight * extraction_specificity`` score.
        routing: Deterministic routing action (``AUTO``, ``TRIAGE``, or ``DROP``).
        reasons: Aggregated diagnostics across PURL, grounding, versions, and caps.
    """

    claim: ExtractedPackageClaim
    grounding: GroundingResult
    purl: PurlResolutionResult
    has_valid_version_range: bool
    has_bounded_version_range: bool
    extraction_specificity: float = Field(ge=0.0, le=1.0)
    composite_score: float = Field(ge=0.0, le=1.0)
    routing: RoutingDecision
    reasons: tuple[str, ...] = ()


class CredibilityReport(StrictModel):
    """Advisory-level credibility report aggregating verified and dropped claims.

    Attributes:
        article_url: Source article URI.
        source_tier: Publisher credibility tier.
        source_tier_weight: Numeric weight derived from ``source_tier``.
        extraction_specificity: Highest specificity among accepted claims (or all if all dropped).
        composite_score: Highest composite score across evaluated claims.
        routing: Advisory-level routing outcome.
        claim_results: Every evaluated claim result in input order.
        accepted_claims: Claims routed to ``AUTO`` or ``TRIAGE``.
        dropped_claims: Claims routed to ``DROP``.
        reasons: Advisory-level summary diagnostics.
    """

    article_url: str
    source_tier: SourceTier
    source_tier_weight: float = Field(ge=0.0, le=1.0)
    extraction_specificity: float = Field(ge=0.0, le=1.0)
    composite_score: float = Field(ge=0.0, le=1.0)
    routing: RoutingDecision
    claim_results: tuple[ClaimVerificationResult, ...] = ()
    accepted_claims: tuple[ClaimVerificationResult, ...] = ()
    dropped_claims: tuple[ClaimVerificationResult, ...] = ()
    reasons: tuple[str, ...] = ()


class AssetRef(StrictModel):
    """Cloud-agnostic reference identifying where an inventory component was observed.

    Core models deliberately exclude provider-specific fields (e.g., cloud account IDs or
    regions). Plugins may attach opaque display attributes via ``metadata``.

    Attributes:
        asset_id: Unique identifier (file path, repo slug, digest, or resource ID).
        asset_type: Normalized category (e.g., ``"sbom"``, ``"container_image"``, ``"compute"``).
        backend: Registered inventory backend name (e.g., ``"local_sbom"``).
        scope: Optional organizational, project, cluster, or environment boundary.
        location: Optional manifest path, layer, or regional location string.
        metadata: Bounded opaque key-value attributes attached by a backend plugin.
    """

    asset_id: str
    asset_type: str
    backend: str
    scope: str | None = None
    location: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("asset_id", "asset_type", "backend")
    @classmethod
    def _validate_required_fields(cls, value: str, info: Any) -> str:
        return _require_safe_text(value, str(info.field_name))

    @field_validator("scope", "location")
    @classmethod
    def _validate_optional_fields(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        return _require_safe_text(value, str(info.field_name))

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > MAX_ASSET_METADATA_ENTRIES:
            raise ValueError(f"metadata cannot exceed {MAX_ASSET_METADATA_ENTRIES} entries")
        cleaned: dict[str, str] = {}
        for raw_key, raw_val in value.items():
            key = _require_safe_text(raw_key, "metadata key")
            if len(key) > MAX_ASSET_METADATA_KEY_LENGTH:
                raise ValueError(f"metadata key exceeds {MAX_ASSET_METADATA_KEY_LENGTH} characters")
            if _has_control_chars(raw_val):
                raise ValueError("metadata value must not contain control characters")
            if len(raw_val) > MAX_ASSET_METADATA_VALUE_LENGTH:
                raise ValueError(
                    f"metadata value exceeds {MAX_ASSET_METADATA_VALUE_LENGTH} characters"
                )
            cleaned[key] = raw_val
        return cleaned


class PackageQuery(StrictModel):
    """Query descriptor derived from an OSV affected entry for inventory backends.

    Attributes:
        canonical_purl: Versionless canonical Package URL to search for.
        ecosystem: Canonical PURL ecosystem type (e.g., ``"pypi"``, ``"deb"``).
        osv_ecosystem: Original OSV ecosystem string (e.g., ``"Debian:11"``, ``"PyPI"``).
        namespace: Normalized package namespace/scope/groupId, if any.
        name: Normalized package name.
        distro_release: Normalized OS distro release (e.g., ``"debian-11"``), if qualified.
    """

    canonical_purl: str
    ecosystem: str
    osv_ecosystem: str
    namespace: str | None = None
    name: str
    distro_release: str | None = None

    @field_validator("canonical_purl", "ecosystem", "osv_ecosystem", "name")
    @classmethod
    def _validate_required_fields(cls, value: str, info: Any) -> str:
        return _require_safe_text(value, str(info.field_name))


class InventoryComponent(StrictModel):
    """Normalized software package entry returned by an inventory backend.

    Attributes:
        name: Raw or normalized component package name.
        version: Installed package version string.
        purl: Full raw Package URL string if present in the inventory source.
        canonical_purl: Versionless canonical PURL if resolved cleanly.
        ecosystem: Normalized PURL ecosystem type, if known.
        namespace: Package namespace/scope/groupId, if known.
        distro_qualifier: Raw ``?distro=`` qualifier extracted from PURL or SBOM metadata.
        upstream_package: Source package name from ``?upstream=`` qualifier, if any.
        upstream_version: Source package version embedded in ``?upstream=``, if any.
        asset: Cloud-agnostic :class:`AssetRef` identifying where the component resides.
        bom_ref: Optional CycloneDX ``bom-ref`` or SPDX ``SPDXID`` identifier.
    """

    name: str
    version: str
    purl: str | None = None
    canonical_purl: str | None = None
    ecosystem: str | None = None
    namespace: str | None = None
    distro_qualifier: str | None = None
    upstream_package: str | None = None
    upstream_version: str | None = None
    asset: AssetRef
    bom_ref: str | None = None

    @field_validator("name", "version")
    @classmethod
    def _validate_required_fields(cls, value: str, info: Any) -> str:
        return _require_safe_text(value, str(info.field_name))

    @field_validator(
        "purl",
        "canonical_purl",
        "ecosystem",
        "namespace",
        "distro_qualifier",
        "upstream_package",
        "upstream_version",
        "bom_ref",
    )
    @classmethod
    def _validate_optional_safe_strings(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        if _has_control_chars(value):
            raise ValueError(f"{info.field_name} must not contain control characters")
        stripped = value.strip()
        return stripped or None


class MatchResult(StrictModel):
    """Deterministic match evaluation of an SBOM component against an OSV advisory.

    Attributes:
        advisory_id: Compiled OSV advisory identifier (e.g., ``PRECVE-2026-A3F91C04``).
        component_purl: Original SBOM component PURL (or synthetic fallback identifier).
        installed_version: Installed version string checked against OSV ranges.
        matched_purl: Canonical package PURL from the advisory that matched.
        ecosystem: OSV ecosystem string used for version math.
        is_vulnerable: True when ``installed_version`` falls within an affected range/version.
        matched_range: Human-readable summary of evaluated ranges/versions.
        fixed_versions: Deduplicated fixed version strings from the advisory.
        evidence_quote: Grounded quote supporting the matched advisory claim.
        sbom_source: Optional filename or backend location for the evaluated component.
        asset: Optional cloud-agnostic :class:`AssetRef` associated with the component.
        matched_via: Mechanism used to link component to advisory (``purl``, ``upstream``, or
            ``name_fallback``).
    """

    advisory_id: str
    component_purl: str
    installed_version: str
    matched_purl: str
    ecosystem: str
    is_vulnerable: bool
    matched_range: str | None = None
    fixed_versions: tuple[str, ...] = ()
    evidence_quote: str | None = None
    sbom_source: str | None = None
    asset: AssetRef | None = None
    matched_via: Literal["purl", "upstream", "name_fallback"] = "purl"


class OsvPackage(StrictModel):
    """OSV schema ``affected[].package`` object."""

    ecosystem: str
    name: str
    purl: str

    @field_validator("ecosystem", "name", "purl")
    @classmethod
    def _validate_non_empty(cls, value: str, info: Any) -> str:
        return _require_safe_text(value, str(info.field_name))


class OsvRangeEvent(StrictModel):
    """OSV schema range event object containing exactly one boundary key."""

    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    limit: str | None = None

    @model_validator(mode="after")
    def _validate_single_key(self) -> OsvRangeEvent:
        """Ensure exactly one OSV range event boundary key is populated."""
        fields = (self.introduced, self.fixed, self.last_affected, self.limit)
        present = [val for val in fields if val is not None]
        if len(present) != 1:
            raise ValueError(
                "OsvRangeEvent must set exactly one of introduced, fixed, last_affected, or limit"
            )
        if not present[0].strip():
            raise ValueError("OsvRangeEvent value must not be empty or whitespace-only")
        return self


class OsvRange(StrictModel):
    """OSV schema ``affected[].ranges[]`` object."""

    type: Literal["ECOSYSTEM", "SEMVER", "GIT"]
    events: tuple[OsvRangeEvent, ...]

    @model_validator(mode="after")
    def _validate_events(self) -> OsvRange:
        """Ensure the event stream is non-empty and starts with an ``introduced`` event."""
        if not self.events:
            raise ValueError("OsvRange.events must not be empty")
        if self.events[0].introduced is None:
            raise ValueError("First event in OsvRange.events must define 'introduced'")
        return self


class OsvAffected(StrictModel):
    """OSV schema ``affected[]`` package entry."""

    package: OsvPackage
    ranges: tuple[OsvRange, ...] = ()
    versions: tuple[str, ...] = ()
    database_specific: dict[str, Any] | None = None


class OsvReference(StrictModel):
    """OSV schema ``references[]`` entry."""

    type: Literal[
        "ADVISORY",
        "ARTICLE",
        "DETECTION",
        "DISCUSSION",
        "REPORT",
        "FIX",
        "INTRODUCED",
        "GIT",
        "PACKAGE",
        "EVIDENCE",
        "WEB",
    ]
    url: str

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        return _require_uri(value, "url")


class OsvAdvisory(StrictModel):
    """Standard OSV v1.6.7 JSON advisory contract.

    Attributes:
        schema_version: OSV schema version string (defaults to ``"1.6.7"``).
        id: Unique advisory identifier (e.g., ``PRECVE-2026-A3F91C04``).
        modified: Last modification timestamp.
        published: Initial publication timestamp.
        summary: Short vulnerability summary.
        details: Detailed writeup text.
        aliases: Known upstream CVE/GHSA identifiers, if any.
        affected: Non-empty tuple of affected packages and version ranges.
        references: Supporting article, fix, PoC, and web URLs.
        database_specific: Extension metadata (stores ``zerobom`` credibility context).
    """

    schema_version: str = "1.6.7"
    id: str
    modified: datetime
    published: datetime
    summary: str
    details: str = ""
    aliases: tuple[str, ...] = ()
    affected: tuple[OsvAffected, ...]
    references: tuple[OsvReference, ...] = ()
    database_specific: dict[str, Any] = Field(default_factory=dict)

    @field_validator("id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        if _has_control_chars(value):
            raise ValueError("OsvAdvisory.id must not contain control characters")
        stripped = _require_non_empty_str(value, "id")
        if any(ch.isspace() for ch in stripped):
            raise ValueError("OsvAdvisory.id must not contain whitespace")
        return stripped

    @model_validator(mode="after")
    def _validate_affected(self) -> OsvAdvisory:
        """Require at least one affected package entry per OSV schema."""
        if not self.affected:
            raise ValueError("OsvAdvisory.affected must contain at least one affected entry")
        return self

    def to_osv_dict(self) -> dict[str, Any]:
        """Serialize this advisory to an OSV v1.6 JSON-compatible dictionary.

        Returns:
            Dictionary conforming to the OSV v1.6 JSON schema with RFC 3339 UTC ``Z``
            timestamps and empty optional collections omitted.
        """
        data: dict[str, Any] = self.model_dump(mode="json", exclude_none=True)
        data["modified"] = _format_rfc3339_utc(self.modified)
        data["published"] = _format_rfc3339_utc(self.published)

        if not self.aliases:
            data.pop("aliases", None)
        if not self.references:
            data.pop("references", None)
        if not self.database_specific:
            data.pop("database_specific", None)

        cleaned_affected: list[dict[str, Any]] = []
        for item in data.get("affected", []):
            if not item.get("ranges"):
                item.pop("ranges", None)
            if not item.get("versions"):
                item.pop("versions", None)
            cleaned_affected.append(item)
        data["affected"] = cleaned_affected

        return data


class PipelineOutcome(StrictModel):
    """End-to-end result of running an article or OSV advisory through the zerobom pipeline.

    Attributes:
        article: Ingested source article, if applicable (``None`` in pure ``scan`` mode).
        prefilter: Deterministic pre-filter result when pre-filtering executed.
        advisory: Extracted advisory candidate when extraction executed.
        credibility: Verification and two-axis credibility report.
        osv: Compiled OSV v1.6.7 advisory if at least one claim survived verification.
        matches: Inventory match evaluations returned by the configured backend.
        skipped_reason: Diagnostic reason when an article stopped early (e.g., prefilter drop).
    """

    article: RawArticle | None = None
    prefilter: PrefilterResult | None = None
    advisory: ExtractedAdvisory | None = None
    credibility: CredibilityReport | None = None
    osv: OsvAdvisory | None = None
    matches: tuple[MatchResult, ...] = ()
    skipped_reason: str | None = None

    @property
    def vulnerable_matches(self) -> tuple[MatchResult, ...]:
        """Return only vulnerable :class:`MatchResult` entries."""
        return tuple(match for match in self.matches if match.is_vulnerable)

    @property
    def has_vulnerable_hits(self) -> bool:
        """Return True if at least one vulnerable inventory component matched."""
        return any(match.is_vulnerable for match in self.matches)
