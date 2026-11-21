"""Deterministic OSV JSON compiler and ``univers``-backed version-range evaluator.

This module bridges verified package claims and standard Open Source Vulnerability (OSV)
v1.6.7 JSON documents without relying on an LLM for version comparison or schema synthesis.

Key invariants:

- **Deterministic Version Math:** All parsing and interval membership evaluations delegate to
  ``univers`` ecosystem-native version classes (PEP 440, SemVer, Maven, Debian ``dpkg``, Go).
- **OSV ``"0"`` Sentinel Handling:** Because ``univers`` evaluates an empty constraint list as
  non-matching, intervals starting at ``introduced="0"`` either pass only the upper-bound
  constraint to ``univers`` or evaluate to ``True`` for all valid ecosystem versions when
  unbounded.
- **No Runtime ``assert``:** Missing metadata fails closed cleanly via explicit conditional
  guards rather than ``assert`` statements (which ``python -O`` strips).
- **Resource & ReDoS Bounds:** Enforces strict upper length limits and rejects control
  characters on untrusted version strings and raw specifiers before regex evaluation.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from packageurl import PackageURL
from univers.version_constraint import VersionConstraint as UniversVersionConstraint
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.versions import InvalidVersion

from zerobom.models import (
    AssetRef,
    CredibilityReport,
    ExtractedAdvisory,
    InventoryComponent,
    MatchResult,
    OsvAdvisory,
    OsvAffected,
    OsvPackage,
    OsvRange,
    OsvRangeEvent,
    OsvReference,
    PackageQuery,
    RawArticle,
    RoutingDecision,
    VersionConstraint,
)
from zerobom.verify.purl import (
    _DISTRO_PURL_TYPES,
    _RUNTIME_FRIENDLY_PURL_TYPES,
    GENERIC_PACKAGE_BLOCKLIST,
    REGISTRY_ONLY_GENERIC_BLOCKLIST,
    _normalize_pep503,
    _split_namespace_and_name,
    normalize_ecosystem,
)

MAX_VERSION_LENGTH = 128
MAX_SPECIFIER_LENGTH = 256

_SEMVER_PURL_TYPES: frozenset[str] = frozenset({"npm", "golang", "cargo"})
_TRACKING_QUERY_PARAMS: frozenset[str] = frozenset({"ref", "fbclid", "gclid", "mc_cid", "mc_eid"})

_NL_LESS_RE = re.compile(
    r"^(?:all\s+versions?\s+)?(?:prior\s+to|before|earlier\s+than|below|under|"
    r"fixed\s+in(?:\s+version)?|patched\s+in(?:\s+version)?)\s+([^\s,;]+)$",
    re.IGNORECASE,
)
_NL_LEQ_PREFIX_RE = re.compile(
    r"^(?:all\s+versions?\s+)?(?:up\s+to|through)\s+(?:and\s+including\s+)?([^\s,;]+)$",
    re.IGNORECASE,
)
_NL_LEQ_SUFFIX_RE = re.compile(
    r"^([^\s,;]+)\s+and\s+(?:earlier|prior|older|below)$",
    re.IGNORECASE,
)
_NL_BETWEEN_RE = re.compile(
    r"^(?:from\s+)?([^\s,;]+)\s+(?:to|through)\s+([^\s,;]+)$",
    re.IGNORECASE,
)
_NL_FROM_BEFORE_RE = re.compile(
    r"^from\s+([^\s,;]+)\s+(?:before|prior\s+to|up\s+to)\s+([^\s,;]+)$",
    re.IGNORECASE,
)
_HYPHEN_RANGE_RE = re.compile(r"^([^\s,;]+)\s+-\s+([^\s,;]+)$")
_COMPARATOR_TOKEN_RE = re.compile(r"^(>=|<=|==|<|>|=)\s*([^\s,;]+)$")
_DISTRO_FAMILY_RE = re.compile(
    r"^(debian|ubuntu|alpine|redhat-enterprise-linux|enterprise-linux|redhat|rhel|"
    r"centos|fedora|rocky|almalinux|cloudlinux|suse|sles|opensuse|oraclelinux|oracle|"
    r"amazonlinux|amzn|azurelinux|mariner|wolfi|chainguard)[-_:]?v?(\d+(?:\.\d+)*)$",
    re.IGNORECASE,
)
_DISTRO_CODENAME_ALIASES: dict[str, str] = {
    "buster": "debian-10",
    "debian-buster": "debian-10",
    "bullseye": "debian-11",
    "debian-bullseye": "debian-11",
    "bookworm": "debian-12",
    "debian-bookworm": "debian-12",
    "trixie": "debian-13",
    "debian-trixie": "debian-13",
    "focal": "ubuntu-20.04",
    "ubuntu-focal": "ubuntu-20.04",
    "jammy": "ubuntu-22.04",
    "ubuntu-jammy": "ubuntu-22.04",
    "noble": "ubuntu-24.04",
    "ubuntu-noble": "ubuntu-24.04",
}
_TWO_PART_RELEASE_DISTROS: frozenset[str] = frozenset({"ubuntu", "alpine"})


def _has_control_chars(value: str) -> bool:
    """Return True if value contains any ASCII control character (including CRLF or NUL)."""
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


@dataclass(frozen=True)
class ParsedConstraint:
    """Deterministic parse outcome of a single :class:`VersionConstraint`.

    Attributes:
        events: Compiled OSV range events when representing an interval.
        exact_version: Single matched version string when representing an exact constraint.
        is_bounded: True if the constraint specifies an upper bound or exact version.
        is_valid: True when all bounds parsed validly and were non-inverted.
        reason: Failure explanation when ``is_valid`` is ``False``.
    """

    events: tuple[OsvRangeEvent, ...]
    exact_version: str | None
    is_bounded: bool
    is_valid: bool
    reason: str | None = None


def normalize_distro_qualifier(raw_distro: str | None) -> str | None:
    """Normalize an OS distro qualifier or release tag into ``{family}-{release}``.

    Handles values such as ``"debian-11"``, ``"debian-11.8"``, ``"ubuntu-22.04"``,
    ``"alpine-v3.19"``, ``"alpine-3.19.1"``, ``"Red Hat:enterprise_linux:9"``, and common
    Debian/Ubuntu codenames.

    Args:
        raw_distro: Unnormalized distro qualifier string.

    Returns:
        Canonical distro release identifier (e.g., ``"debian-11"``, ``"alpine-3.19"``), or
        ``None`` if empty or invalid.
    """
    if raw_distro is None or _has_control_chars(raw_distro):
        return None
    cleaned = raw_distro.strip().lower()
    if not cleaned:
        return None

    normalized_sep = re.sub(r"[\s_:]+", "-", cleaned)
    normalized_sep = normalized_sep.replace("red-hat", "redhat")

    if normalized_sep in _DISTRO_CODENAME_ALIASES:
        return _DISTRO_CODENAME_ALIASES[normalized_sep]

    if match := _DISTRO_FAMILY_RE.match(normalized_sep):
        raw_family, raw_version = match.group(1).lower(), match.group(2)
        family = (
            "rhel"
            if raw_family in {"redhat", "rhel", "redhat-enterprise-linux", "enterprise-linux"}
            else raw_family
        )
        parts = raw_version.split(".")
        if family in _TWO_PART_RELEASE_DISTROS and len(parts) >= 2:
            release = f"{parts[0]}.{parts[1]}"
        else:
            release = parts[0]
        return f"{family}-{release}"

    return normalized_sep


def parse_osv_ecosystem(osv_ecosystem: str) -> tuple[str, str | None]:
    """Split an OSV ecosystem string into ``(base_ecosystem, normalized_distro_release)``.

    Args:
        osv_ecosystem: OSV ecosystem string (e.g., ``"Debian:11"``, ``"Alpine:v3.19"``,
            ``"PyPI"``).

    Returns:
        Tuple containing the base ecosystem name and optional normalized distro release.
    """
    cleaned = osv_ecosystem.strip()
    if ":" in cleaned:
        base_part, release_part = cleaned.split(":", 1)
        rel_clean = release_part.strip()
        purl_type, canonical_base = normalize_ecosystem(base_part)
        if purl_type in {"deb", "rpm", "apk"} and canonical_base is not None:
            family_hint = "rhel" if purl_type == "rpm" and "red" in base_part.lower() else base_part
            family_slug = family_hint.strip().lower()
            rel_norm = re.sub(r"[\s_:]+", "-", rel_clean.lower())
            el_match = (
                re.match(r"^el(\d+(?:[._]\d+)*)$", rel_clean, re.IGNORECASE)
                if purl_type == "rpm"
                else None
            )
            if (
                "enterprise_linux" in rel_clean.lower()
                or _DISTRO_FAMILY_RE.match(rel_norm)
                or rel_norm.startswith(f"{family_slug}-")
            ):
                candidate = rel_clean
            elif el_match is not None:
                el_release = el_match.group(1).replace("_", ".")
                candidate = f"{family_hint.strip()}-{el_release}"
            else:
                candidate = f"{family_hint.strip()}-{rel_clean}"
            return canonical_base, normalize_distro_qualifier(candidate)
        if purl_type is None and base_part.strip() and rel_clean:
            rel_norm = re.sub(r"[\s_:]+", "-", rel_clean.lower())
            base_slug = base_part.strip().lower()
            if rel_norm.startswith(f"{base_slug}-"):
                return base_part.strip(), normalize_distro_qualifier(rel_clean)
            return base_part.strip(), normalize_distro_qualifier(f"{base_part.strip()}-{rel_clean}")
    return cleaned, None


def is_distro_compatible(advisory_release: str | None, component_distro: str | None) -> bool:
    """Return True if advisory and component distro releases are compatible or unspecified.

    Args:
        advisory_release: Optional release extracted from the advisory ecosystem.
        component_distro: Optional ``?distro=`` qualifier extracted from the SBOM component.

    Returns:
        ``True`` if either side is unspecified (``None``) or both normalize identically.
    """
    if advisory_release is None or component_distro is None:
        return True
    norm_adv = normalize_distro_qualifier(advisory_release)
    norm_comp = normalize_distro_qualifier(component_distro)
    if norm_adv is None or norm_comp is None:
        return True
    return norm_adv == norm_comp


def extract_purl_os_qualifiers(purl_str: str) -> tuple[str | None, str | None, str | None]:
    """Extract ``(distro_qualifier, upstream_name, upstream_version)`` from a PURL string.

    Args:
        purl_str: Raw Package URL string (possibly carrying ``?distro=...&upstream=...``).

    Returns:
        Tuple of ``(distro_qualifier, upstream_package_name, upstream_version)``.
    """
    parsed = PackageURL.from_string(purl_str.strip())
    qualifiers = parsed.qualifiers
    if not isinstance(qualifiers, dict):
        return None, None, None

    raw_distro = qualifiers.get("distro")
    distro = raw_distro.strip() if isinstance(raw_distro, str) and raw_distro.strip() else None

    raw_upstream = qualifiers.get("upstream")
    if not isinstance(raw_upstream, str) or not raw_upstream.strip():
        return distro, None, None

    upstream_text = raw_upstream.strip()
    if "@" in upstream_text:
        up_name, up_ver = upstream_text.split("@", 1)
        return distro, up_name.strip() or None, up_ver.strip() or None
    if " (" in upstream_text and upstream_text.endswith(")"):
        up_name, up_ver_part = upstream_text[:-1].split(" (", 1)
        return distro, up_name.strip() or None, up_ver_part.strip() or None

    return distro, upstream_text, None


def _resolve_univers_scheme(ecosystem: str) -> str:
    """Map a PURL type or OSV ecosystem name to a ``univers`` ``RANGE_CLASS_BY_SCHEMES`` key."""
    base_ecosystem, _ = parse_osv_ecosystem(ecosystem)
    purl_type, _ = normalize_ecosystem(base_ecosystem)
    key = purl_type if purl_type is not None else base_ecosystem.strip().lower()
    if key in RANGE_CLASS_BY_SCHEMES:
        return key
    raise ValueError(f"Unsupported ecosystem for univers version math: '{ecosystem}'")


def _get_range_class(ecosystem: str) -> Any:
    """Return the ``univers`` ``VersionRange`` subclass for an ecosystem."""
    scheme = _resolve_univers_scheme(ecosystem)
    return RANGE_CLASS_BY_SCHEMES[scheme]


def parse_ecosystem_version(ecosystem: str, version_str: str) -> Any:
    """Parse a version string using the ecosystem's native ``univers`` Version class.

    Args:
        ecosystem: Ecosystem alias, canonical PURL type, or OSV ecosystem name.
        version_str: Untrusted version string to parse.

    Returns:
        An ecosystem-native ``univers`` version object supporting ordering comparisons.

    Raises:
        ValueError: If the version contains control characters or whitespace, exceeds
            ``MAX_VERSION_LENGTH``, the ecosystem is unsupported, or ``univers`` rejects it.
    """
    if _has_control_chars(version_str):
        raise ValueError("Version string must not contain control characters")
    cleaned = version_str.strip()
    if len(cleaned) > MAX_VERSION_LENGTH:
        raise ValueError(f"Version string exceeds maximum length of {MAX_VERSION_LENGTH} chars")
    if not cleaned or any(ch.isspace() for ch in cleaned):
        raise ValueError(f"Invalid empty or whitespace version string: {version_str!r}")
    range_cls = _get_range_class(ecosystem)
    version_cls = range_cls.version_class
    try:
        return version_cls(cleaned)
    except (InvalidVersion, ValueError, TypeError) as exc:
        raise ValueError(f"Invalid version {cleaned!r} for ecosystem {ecosystem!r}: {exc}") from exc


def strip_package_nvr_prefix(version_str: str, package_name: str | None) -> str:
    """Strip a redundant ``<package_name>-`` NVR prefix when followed by an ASCII digit.

    For example, converts RPM/DEB build NVR strings such as
    ``kernel-5.14.0-687.60.1.el9_8`` (given ``package_name="kernel"``) into
    ``5.14.0-687.60.1.el9_8``. Unrelated strings or non-digit suffixes are returned
    trimmed and unmodified.

    Args:
        version_str: Raw extracted version or NVR token.
        package_name: Canonical package name associated with the claim.

    Returns:
        Normalized version string with redundant package-name prefix stripped if valid.
    """
    cleaned = version_str.strip()
    if not cleaned or not package_name:
        return cleaned
    pkg = package_name.strip().lower()
    if not pkg:
        return cleaned
    prefix = f"{pkg}-"
    if cleaned.lower().startswith(prefix):
        remainder = cleaned[len(prefix) :]
        if remainder and remainder[0].isdigit():
            return remainder
    return cleaned


def _normalize_bound_version(value: str, package_name: str | None) -> str:
    """Trim a version bound and strip an optional ``<package_name>-`` NVR prefix."""
    cleaned = value.strip()
    if cleaned == "0":
        return "0"
    return strip_package_nvr_prefix(cleaned, package_name)


def _build_interval_parsed_constraint(
    ecosystem: str,
    *,
    introduced: str,
    fixed: str | None = None,
    last_affected: str | None = None,
    package_name: str | None = None,
) -> ParsedConstraint:
    """Validate lower and upper bounds against ``univers`` and compile OSV interval events."""
    intro_clean = _normalize_bound_version(introduced, package_name) or "0"
    try:
        # OSV sentinel "0" denotes origin (before any released version) and is not ecosystem-parsed.
        lo_ver = None if intro_clean == "0" else parse_ecosystem_version(ecosystem, intro_clean)
        if fixed is not None:
            fixed_clean = _normalize_bound_version(fixed, package_name)
            hi_ver = parse_ecosystem_version(ecosystem, fixed_clean)
            if lo_ver is not None and lo_ver >= hi_ver:
                return ParsedConstraint(
                    events=(),
                    exact_version=None,
                    is_bounded=False,
                    is_valid=False,
                    reason=(
                        f"Inverted version bounds: introduced {intro_clean!r} >= "
                        f"fixed {fixed_clean!r}."
                    ),
                )
            return ParsedConstraint(
                events=(OsvRangeEvent(introduced=intro_clean), OsvRangeEvent(fixed=fixed_clean)),
                exact_version=None,
                is_bounded=True,
                is_valid=True,
            )

        if last_affected is not None:
            la_clean = _normalize_bound_version(last_affected, package_name)
            hi_ver = parse_ecosystem_version(ecosystem, la_clean)
            if lo_ver is not None and lo_ver > hi_ver:
                return ParsedConstraint(
                    events=(),
                    exact_version=None,
                    is_bounded=False,
                    is_valid=False,
                    reason=(
                        f"Inverted version bounds: introduced {intro_clean!r} > "
                        f"last_affected {la_clean!r}."
                    ),
                )
            return ParsedConstraint(
                events=(
                    OsvRangeEvent(introduced=intro_clean),
                    OsvRangeEvent(last_affected=la_clean),
                ),
                exact_version=None,
                is_bounded=True,
                is_valid=True,
            )

        return ParsedConstraint(
            events=(OsvRangeEvent(introduced=intro_clean),),
            exact_version=None,
            is_bounded=False,
            is_valid=True,
        )
    except ValueError as exc:
        return ParsedConstraint(
            events=(),
            exact_version=None,
            is_bounded=False,
            is_valid=False,
            reason=str(exc),
        )


def _parse_raw_specifier(
    ecosystem: str,
    raw_specifier: str,
    *,
    package_name: str | None = None,
) -> ParsedConstraint:
    """Parse comparator lists, hyphen ranges, and common prose version expressions."""
    if _has_control_chars(raw_specifier):
        return ParsedConstraint(
            events=(),
            exact_version=None,
            is_bounded=False,
            is_valid=False,
            reason="Version specifier contains control characters.",
        )
    if len(raw_specifier) > MAX_SPECIFIER_LENGTH:
        return ParsedConstraint(
            events=(),
            exact_version=None,
            is_bounded=False,
            is_valid=False,
            reason=f"Version specifier exceeds maximum length of {MAX_SPECIFIER_LENGTH} chars.",
        )

    spec = re.sub(r"\s+", " ", raw_specifier.strip())
    lowered = spec.lower()

    if lowered in {"*", "all", "all versions", "any", "any version"}:
        return ParsedConstraint(
            events=(OsvRangeEvent(introduced="0"),),
            exact_version=None,
            is_bounded=False,
            is_valid=True,
        )

    if match := _NL_LESS_RE.match(spec):
        return _build_interval_parsed_constraint(
            ecosystem,
            introduced="0",
            fixed=match.group(1),
            package_name=package_name,
        )

    if match := _NL_LEQ_PREFIX_RE.match(spec):
        return _build_interval_parsed_constraint(
            ecosystem,
            introduced="0",
            last_affected=match.group(1),
            package_name=package_name,
        )

    if match := _NL_LEQ_SUFFIX_RE.match(spec):
        return _build_interval_parsed_constraint(
            ecosystem,
            introduced="0",
            last_affected=match.group(1),
            package_name=package_name,
        )

    if match := _NL_FROM_BEFORE_RE.match(spec):
        return _build_interval_parsed_constraint(
            ecosystem,
            introduced=match.group(1),
            fixed=match.group(2),
            package_name=package_name,
        )

    if match := _NL_BETWEEN_RE.match(spec):
        return _build_interval_parsed_constraint(
            ecosystem,
            introduced=match.group(1),
            last_affected=match.group(2),
            package_name=package_name,
        )

    if match := _HYPHEN_RANGE_RE.match(spec):
        return _build_interval_parsed_constraint(
            ecosystem,
            introduced=match.group(1),
            last_affected=match.group(2),
            package_name=package_name,
        )

    # Comparator list: ">= 1.2.0, < 1.5.4", "<2.31.0", "== 1.0.0"
    parts = [
        p.strip() for p in re.split(r"[,;]+|\s+and\s+", spec, flags=re.IGNORECASE) if p.strip()
    ]
    if not parts:
        return ParsedConstraint(
            events=(),
            exact_version=None,
            is_bounded=False,
            is_valid=False,
            reason=f"Empty version specifier: {raw_specifier!r}",
        )

    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    exact: str | None = None

    for part in parts:
        comp_match = _COMPARATOR_TOKEN_RE.match(part)
        if not comp_match:
            return ParsedConstraint(
                events=(),
                exact_version=None,
                is_bounded=False,
                is_valid=False,
                reason=f"Unrecognized version specifier expression: {part!r}",
            )
        op, ver = comp_match.group(1), comp_match.group(2)
        if op == ">":
            # Reject strict '>' rather than silently approximating with inclusive '>=' in OSV.
            return ParsedConstraint(
                events=(),
                exact_version=None,
                is_bounded=False,
                is_valid=False,
                reason=(
                    f"Strict '>' comparator ({part!r}) cannot be converted accurately to OSV "
                    "introduced events."
                ),
            )
        if op in {"==", "="}:
            if exact is not None or introduced is not None or fixed or last_affected:
                return ParsedConstraint(
                    events=(),
                    exact_version=None,
                    is_bounded=False,
                    is_valid=False,
                    reason=f"Conflicting exact comparator in {raw_specifier!r}",
                )
            exact = ver
        elif op == ">=":
            if introduced is not None or exact is not None:
                return ParsedConstraint(
                    events=(),
                    exact_version=None,
                    is_bounded=False,
                    is_valid=False,
                    reason=f"Duplicate or conflicting lower bound in {raw_specifier!r}",
                )
            introduced = ver
        elif op == "<":
            if fixed is not None or last_affected is not None or exact is not None:
                return ParsedConstraint(
                    events=(),
                    exact_version=None,
                    is_bounded=False,
                    is_valid=False,
                    reason=f"Duplicate or conflicting upper bound in {raw_specifier!r}",
                )
            fixed = ver
        elif op == "<=":
            if fixed is not None or last_affected is not None or exact is not None:
                return ParsedConstraint(
                    events=(),
                    exact_version=None,
                    is_bounded=False,
                    is_valid=False,
                    reason=f"Duplicate or conflicting upper bound in {raw_specifier!r}",
                )
            last_affected = ver

    if exact is not None:
        exact_clean = _normalize_bound_version(exact, package_name)
        try:
            parse_ecosystem_version(ecosystem, exact_clean)
        except ValueError as exc:
            return ParsedConstraint(
                events=(),
                exact_version=None,
                is_bounded=False,
                is_valid=False,
                reason=str(exc),
            )
        return ParsedConstraint(
            events=(),
            exact_version=exact_clean,
            is_bounded=True,
            is_valid=True,
        )

    return _build_interval_parsed_constraint(
        ecosystem,
        introduced=introduced if introduced is not None else "0",
        fixed=fixed,
        last_affected=last_affected,
        package_name=package_name,
    )


def parse_version_constraint(
    ecosystem: str,
    constraint: VersionConstraint,
    *,
    package_name: str | None = None,
) -> ParsedConstraint:
    """Deterministically parse and validate a :class:`VersionConstraint` for an ecosystem.

    Args:
        ecosystem: Ecosystem alias, canonical PURL type, or OSV ecosystem name.
        constraint: Structured raw constraint to validate and compile.
        package_name: Optional canonical package name used to strip redundant NVR prefixes.

    Returns:
        A :class:`ParsedConstraint` containing validated OSV events or an exact version.
    """
    try:
        _get_range_class(ecosystem)
    except ValueError as exc:
        return ParsedConstraint(
            events=(),
            exact_version=None,
            is_bounded=False,
            is_valid=False,
            reason=str(exc),
        )

    if constraint.exact is not None:
        exact_clean = _normalize_bound_version(constraint.exact, package_name)
        try:
            parse_ecosystem_version(ecosystem, exact_clean)
        except ValueError as exc:
            return ParsedConstraint(
                events=(),
                exact_version=None,
                is_bounded=False,
                is_valid=False,
                reason=str(exc),
            )
        return ParsedConstraint(
            events=(),
            exact_version=exact_clean,
            is_bounded=True,
            is_valid=True,
        )

    if constraint.is_unbounded:
        intro = (
            _normalize_bound_version(constraint.introduced, package_name)
            if constraint.introduced is not None
            else "0"
        )
        if intro != "0":
            try:
                parse_ecosystem_version(ecosystem, intro)
            except ValueError as exc:
                return ParsedConstraint(
                    events=(),
                    exact_version=None,
                    is_bounded=False,
                    is_valid=False,
                    reason=str(exc),
                )
        return ParsedConstraint(
            events=(OsvRangeEvent(introduced=intro),),
            exact_version=None,
            is_bounded=False,
            is_valid=True,
        )

    if (
        constraint.introduced is not None
        or constraint.fixed is not None
        or constraint.last_affected is not None
    ):
        return _build_interval_parsed_constraint(
            ecosystem,
            introduced=constraint.introduced if constraint.introduced is not None else "0",
            fixed=constraint.fixed,
            last_affected=constraint.last_affected,
            package_name=package_name,
        )

    if constraint.raw_specifier is not None:
        return _parse_raw_specifier(
            ecosystem,
            constraint.raw_specifier,
            package_name=package_name,
        )

    return ParsedConstraint(
        events=(),
        exact_version=None,
        is_bounded=False,
        is_valid=False,
        reason="VersionConstraint contained no parseable version fields.",
    )


def validate_claim_versions(
    ecosystem: str | None,
    constraints: Sequence[VersionConstraint],
    *,
    package_name: str | None = None,
) -> tuple[bool, bool, tuple[str, ...]]:
    """Validate all version constraints for a claim and report validity and boundedness.

    Args:
        ecosystem: Canonical PURL ecosystem type or OSV ecosystem name.
        constraints: Sequence of constraints attached to a package claim.
        package_name: Optional canonical package name used to strip redundant NVR prefixes.

    Returns:
        Tuple of ``(has_valid_version_range, has_bounded_version_range, failure_reasons)``.
    """
    if not constraints:
        return False, False, ("No version constraints provided.",)
    if ecosystem is None:
        return False, False, ("Ecosystem is unknown; cannot validate versions.",)

    try:
        _get_range_class(ecosystem)
    except ValueError as exc:
        return False, False, (str(exc),)

    parsed = [
        parse_version_constraint(ecosystem, item, package_name=package_name) for item in constraints
    ]
    reasons = tuple(item.reason for item in parsed if not item.is_valid and item.reason)
    all_valid = all(item.is_valid for item in parsed)
    has_bounded = all_valid and any(item.is_bounded for item in parsed)
    return all_valid, has_bounded, reasons


def canonicalize_url(url: str) -> str:
    """Canonicalize an article URL for deterministic advisory ID generation.

    Lowercases scheme and host, strips URL fragments and trailing slashes, removes common
    marketing/tracking query parameters (e.g., ``utm_*``, ``fbclid``), and sorts remaining
    query parameters.

    Args:
        url: Source article URI string.

    Returns:
        Normalized canonical URL string.
    """
    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")

    filtered_params = [
        (k, v)
        for k, v in parse_qsl(parsed.query, keep_blank_values=True)
        if not k.lower().startswith("utm_") and k.lower() not in _TRACKING_QUERY_PARAMS
    ]
    filtered_params.sort()
    query = urlencode(filtered_params, doseq=True)
    return urlunparse((scheme, netloc, path, parsed.params, query, ""))


def generate_precve_id(
    article_url: str,
    purls: Sequence[str],
    published_at: datetime | None = None,
) -> str:
    """Generate a reproducible ``PRECVE-YYYY-XXXXXXXX`` identifier from URL and PURLs.

    Args:
        article_url: Source article URI.
        purls: Canonical PURLs included in the advisory.
        published_at: Optional publication date used for the ``YYYY`` segment.

    Returns:
        Deterministic advisory identifier formatted as ``PRECVE-YYYY-XXXXXXXX``.
    """
    year = (published_at or datetime.now(UTC)).year
    canonical_purls = "|".join(sorted(set(purls)))
    payload = f"{canonicalize_url(article_url)}|{canonical_purls}".encode()
    digest = hashlib.sha256(payload).hexdigest()[:8].upper()
    return f"PRECVE-{year}-{digest}"


def _osv_package_name(purl_type: str, namespace: str | None, name: str) -> str:
    """Format package name according to OSV ecosystem conventions."""
    if purl_type == "maven":
        return f"{namespace}:{name}" if namespace else name
    if purl_type in {"npm", "golang", "composer"}:
        return f"{namespace}/{name}" if namespace else name
    return name


def _osv_range_type(purl_type: str) -> Literal["ECOSYSTEM", "SEMVER", "GIT"]:
    """Select OSV range type (``SEMVER`` vs ``ECOSYSTEM``) for a PURL type."""
    return "SEMVER" if purl_type in _SEMVER_PURL_TYPES else "ECOSYSTEM"


def _format_claim_osv_ecosystem(
    base_osv_ecosystem: str,
    purl_type: str,
    distro_release: str | None,
) -> str:
    """Attach optional OS stream release suffix (e.g., ``CloudLinux:9``) for stream isolation."""
    if purl_type in _DISTRO_PURL_TYPES and distro_release and ":" not in base_osv_ecosystem:
        return f"{base_osv_ecosystem}:{distro_release}"
    return base_osv_ecosystem


def compile_osv_advisory(
    advisory: ExtractedAdvisory,
    report: CredibilityReport,
    *,
    article: RawArticle | None = None,
    advisory_id: str | None = None,
    modified_at: datetime | None = None,
) -> OsvAdvisory | None:
    """Compile accepted, verified claims into a standard OSV v1.6.7 advisory.

    Args:
        advisory: Original extracted advisory candidate.
        report: Verification and credibility report containing ``accepted_claims``.
        article: Optional source :class:`RawArticle` providing publisher metadata and dates.
        advisory_id: Optional explicit identifier overriding deterministic ``PRECVE`` hashing.
        modified_at: Optional modification timestamp overriding ``published``.

    Returns:
        A validated :class:`OsvAdvisory` instance, or ``None`` if no accepted claims remain.
    """
    if not report.accepted_claims:
        return None

    # Prevent lower-confidence TRIAGE claims from piggybacking inside an AUTO advisory.
    if report.routing == RoutingDecision.AUTO:
        eligible_claims = tuple(
            cr for cr in report.accepted_claims if cr.routing == RoutingDecision.AUTO
        )
        held_triage_purls = tuple(
            dict.fromkeys(
                cr.purl.canonical_purl
                for cr in report.accepted_claims
                if cr.routing != RoutingDecision.AUTO and cr.purl.canonical_purl is not None
            )
        )
    else:
        eligible_claims = report.accepted_claims
        held_triage_purls = ()

    if not eligible_claims:
        return None

    grouped: dict[tuple[str, str], list[Any]] = {}
    for claim_result in eligible_claims:
        canonical_purl = claim_result.purl.canonical_purl
        base_osv_eco = claim_result.purl.osv_ecosystem
        purl_type = claim_result.purl.ecosystem
        if canonical_purl is None or base_osv_eco is None or purl_type is None:
            continue
        formatted_eco = _format_claim_osv_ecosystem(
            base_osv_eco,
            purl_type,
            claim_result.claim.distro_release,
        )
        grouped.setdefault((canonical_purl, formatted_eco), []).append(claim_result)

    if not grouped:
        return None

    affected_entries: list[OsvAffected] = []
    for (canonical_purl, group_osv_ecosystem), group_claims in grouped.items():
        first_purl = group_claims[0].purl
        if first_purl.ecosystem is None or first_purl.name is None:
            # Fail closed rather than using assert, which is stripped under python -O.
            continue

        pkg = OsvPackage(
            ecosystem=group_osv_ecosystem,
            name=_osv_package_name(
                first_purl.ecosystem,
                first_purl.namespace,
                first_purl.name,
            ),
            purl=canonical_purl,
        )

        events: list[OsvRangeEvent] = []
        exact_versions: list[str] = []
        seen_exact: set[str] = set()
        group_quotes: list[str] = []
        seen_group_quotes: set[str] = set()

        for claim_result in group_claims:
            for quote in (
                claim_result.claim.evidence_quote,
                *claim_result.claim.supporting_quotes,
            ):
                if quote not in seen_group_quotes:
                    seen_group_quotes.add(quote)
                    group_quotes.append(quote)
            for constraint in claim_result.claim.version_constraints:
                parsed = parse_version_constraint(
                    first_purl.ecosystem,
                    constraint,
                    package_name=first_purl.name,
                )
                if not parsed.is_valid:
                    continue
                if parsed.exact_version is not None:
                    if parsed.exact_version not in seen_exact:
                        seen_exact.add(parsed.exact_version)
                        exact_versions.append(parsed.exact_version)
                elif parsed.events:
                    events.extend(parsed.events)

        ranges: tuple[OsvRange, ...] = ()
        if events:
            ranges = (
                OsvRange(
                    type=_osv_range_type(first_purl.ecosystem),
                    events=tuple(events),
                ),
            )

        # Skip hollow OsvAffected entries when zero valid ranges or exact versions compiled.
        if not ranges and not exact_versions:
            continue

        affected_entries.append(
            OsvAffected(
                package=pkg,
                ranges=ranges,
                versions=tuple(exact_versions),
                database_specific=(
                    {"zerobom": {"evidence_quotes": group_quotes}} if group_quotes else None
                ),
            )
        )

    if not affected_entries:
        return None

    published = (
        advisory.published_at
        or (article.published_at if article is not None else None)
        or datetime.now(UTC)
    )
    modified = modified_at or published

    resolved_id = advisory_id or generate_precve_id(
        advisory.article_url,
        tuple(entry.package.purl for entry in affected_entries),
        published_at=published,
    )

    refs: list[OsvReference] = []
    seen_refs: set[tuple[str, str]] = set()

    def _add_ref(ref_type: Any, url: str | None) -> None:
        if not url:
            return
        cleaned = url.strip()
        if not cleaned:
            return
        key = (str(ref_type), cleaned)
        if key not in seen_refs:
            seen_refs.add(key)
            refs.append(OsvReference(type=ref_type, url=cleaned))

    _add_ref("ARTICLE", advisory.article_url)
    for claim_result in eligible_claims:
        _add_ref("FIX", claim_result.claim.fix_commit_url)
        _add_ref("EVIDENCE", claim_result.claim.poc_url)
    for ref_url in advisory.references:
        _add_ref("WEB", ref_url)

    collected_quotes: list[str] = []
    seen_quotes: set[str] = set()
    for cr in eligible_claims:
        for quote in (cr.claim.evidence_quote, *cr.claim.supporting_quotes):
            if quote not in seen_quotes:
                seen_quotes.add(quote)
                collected_quotes.append(quote)

    zerobom_meta: dict[str, Any] = {
        "source_tier": report.source_tier.value,
        "source_tier_weight": report.source_tier_weight,
        "extraction_specificity": report.extraction_specificity,
        "composite_score": report.composite_score,
        "routing": report.routing.value,
        "severity": advisory.severity.value,
        "cwe_ids": list(advisory.cwe_ids),
        "evidence_quotes": collected_quotes,
    }
    if held_triage_purls:
        zerobom_meta["held_for_triage_purls"] = list(held_triage_purls)
    if article is not None:
        zerobom_meta["source_name"] = article.source_name
    if advisory.prompt_version is not None:
        zerobom_meta["prompt_version"] = advisory.prompt_version
    if advisory.extractor_model is not None:
        zerobom_meta["extractor_model"] = advisory.extractor_model

    return OsvAdvisory(
        id=resolved_id,
        modified=modified,
        published=published,
        summary=advisory.summary,
        details=advisory.details,
        aliases=advisory.known_aliases,
        affected=tuple(affected_entries),
        references=tuple(refs),
        database_specific={"zerobom": zerobom_meta},
    )


def _split_osv_intervals(
    events: Sequence[OsvRangeEvent],
) -> list[tuple[str, OsvRangeEvent | None]]:
    """Split sequential OSV range events into ``(introduced, closing_event)`` intervals."""
    intervals: list[tuple[str, OsvRangeEvent | None]] = []
    open_introduced: str | None = None

    for event in events:
        if event.introduced is not None:
            if open_introduced is not None:
                intervals.append((open_introduced, None))
            open_introduced = event.introduced
        elif open_introduced is not None:
            intervals.append((open_introduced, event))
            open_introduced = None

    if open_introduced is not None:
        intervals.append((open_introduced, None))

    return intervals


def is_version_in_osv_range(
    ecosystem: str,
    installed_version: str,
    osv_range: OsvRange,
) -> bool:
    """Deterministically evaluate whether ``installed_version`` falls within an :class:`OsvRange`.

    Args:
        ecosystem: Ecosystem alias, canonical PURL type, or OSV ecosystem name.
        installed_version: Installed version string from an SBOM or package manifest.
        osv_range: OSV range containing ``introduced`` / ``fixed`` / ``last_affected`` events.

    Returns:
        ``True`` if ``installed_version`` matches any contiguous interval in ``osv_range``.

    Raises:
        ValueError: If ``ecosystem`` is unsupported or any version bound fails parsing.
    """
    range_cls = _get_range_class(ecosystem)
    installed = parse_ecosystem_version(ecosystem, installed_version)
    intervals = _split_osv_intervals(osv_range.events)

    for intro_str, closing_event in intervals:
        # Handle unbounded origin ("0" with no closing event) explicitly because univers
        # VersionRange(constraints=[]).contains(...) returns False.
        if intro_str == "0" and closing_event is None:
            return True

        constraints: list[UniversVersionConstraint] = []
        if intro_str != "0":
            constraints.append(
                UniversVersionConstraint(
                    comparator=">=",
                    version=parse_ecosystem_version(ecosystem, intro_str),
                )
            )
        if closing_event is not None:
            if closing_event.fixed is not None:
                constraints.append(
                    UniversVersionConstraint(
                        comparator="<",
                        version=parse_ecosystem_version(ecosystem, closing_event.fixed),
                    )
                )
            elif closing_event.limit is not None:
                constraints.append(
                    UniversVersionConstraint(
                        comparator="<",
                        version=parse_ecosystem_version(ecosystem, closing_event.limit),
                    )
                )
            elif closing_event.last_affected is not None:
                constraints.append(
                    UniversVersionConstraint(
                        comparator="<=",
                        version=parse_ecosystem_version(ecosystem, closing_event.last_affected),
                    )
                )

        if not constraints:
            continue
        version_range = range_cls(constraints=constraints)
        if bool(version_range.contains(installed)):
            return True

    return False


def _resolve_affected_ecosystem(ecosystem: str, affected: OsvAffected) -> str:
    """Resolve a ``univers``-supported ecosystem key, falling back to PURL type."""
    try:
        _resolve_univers_scheme(ecosystem)
        return ecosystem
    except ValueError:
        if affected.package.purl:
            parsed = PackageURL.from_string(affected.package.purl)
            _resolve_univers_scheme(parsed.type)
            return parsed.type
        raise


def is_version_affected(
    ecosystem: str,
    installed_version: str,
    affected: OsvAffected,
) -> bool:
    """Check whether ``installed_version`` matches an :class:`OsvAffected` entry.

    Evaluates both explicit ``affected.versions`` (using ecosystem-native equality) and
    ``affected.ranges`` (via ``univers`` interval matching).

    Args:
        ecosystem: Ecosystem alias, canonical PURL type, or OSV ecosystem name.
        installed_version: Installed package version string.
        affected: Compiled :class:`OsvAffected` entry.

    Returns:
        ``True`` if the version is vulnerable under exact versions or range intervals.
    """
    resolved_eco = _resolve_affected_ecosystem(ecosystem, affected)
    installed = parse_ecosystem_version(resolved_eco, installed_version)

    for exact_ver in affected.versions:
        if parse_ecosystem_version(resolved_eco, exact_ver) == installed:
            return True

    return any(
        is_version_in_osv_range(resolved_eco, installed_version, osv_range)
        for osv_range in affected.ranges
    )


def _canonicalize_component_purl(purl_str: str) -> tuple[str, str | None]:
    """Extract canonical package PURL (without version/qualifiers) and optional version."""
    parsed = PackageURL.from_string(purl_str.strip())
    purl_type, hinted_osv = normalize_ecosystem(parsed.type)
    canonical_type = purl_type or parsed.type
    norm_ns, norm_name, _ = _split_namespace_and_name(
        purl_type=canonical_type,
        cleaned_name=parsed.name,
        explicit_namespace=parsed.namespace,
        osv_ecosystem=hinted_osv,
    )
    canonical = str(PackageURL(type=canonical_type, namespace=norm_ns, name=norm_name).to_string())
    return canonical, parsed.version


def _build_upstream_canonical(base_canonical_purl: str, upstream_name: str) -> str | None:
    """Build a canonical PURL for an upstream source package in the same ecosystem/namespace."""
    parsed = PackageURL.from_string(base_canonical_purl)
    _, hinted_osv = normalize_ecosystem(parsed.type)
    norm_ns, norm_name, _ = _split_namespace_and_name(
        purl_type=parsed.type,
        cleaned_name=upstream_name,
        explicit_namespace=parsed.namespace,
        osv_ecosystem=hinted_osv,
    )
    if not norm_name:
        return None
    return str(PackageURL(type=parsed.type, namespace=norm_ns, name=norm_name).to_string())


def build_package_queries(advisory: OsvAdvisory) -> tuple[PackageQuery, ...]:
    """Build deduplicated :class:`PackageQuery` entries from an :class:`OsvAdvisory`.

    Args:
        advisory: Compiled OSV advisory containing one or more affected packages.

    Returns:
        Tuple of :class:`PackageQuery` descriptors for query-driven inventory backends.
    """
    queries: list[PackageQuery] = []
    seen: set[tuple[str, str]] = set()

    for affected in advisory.affected:
        canonical_purl, _ = _canonicalize_component_purl(affected.package.purl)
        parsed = PackageURL.from_string(canonical_purl)
        _, distro_release = parse_osv_ecosystem(affected.package.ecosystem)
        key = (canonical_purl, affected.package.ecosystem)
        if key in seen:
            continue
        seen.add(key)
        queries.append(
            PackageQuery(
                canonical_purl=canonical_purl,
                ecosystem=parsed.type,
                osv_ecosystem=affected.package.ecosystem,
                namespace=parsed.namespace,
                name=parsed.name,
                distro_release=distro_release,
            )
        )

    return tuple(queries)


def _format_affected_ranges(affected: OsvAffected) -> str | None:
    """Format compiled OSV ranges and exact versions as a concise human-readable summary."""
    parts: list[str] = []
    for osv_range in affected.ranges:
        for intro_str, closing_event in _split_osv_intervals(osv_range.events):
            seg: list[str] = []
            if intro_str != "0":
                seg.append(f">={intro_str}")
            if closing_event is not None:
                if closing_event.fixed is not None:
                    seg.append(f"<{closing_event.fixed}")
                elif closing_event.limit is not None:
                    seg.append(f"<{closing_event.limit}")
                elif closing_event.last_affected is not None:
                    seg.append(f"<={closing_event.last_affected}")
            parts.append(", ".join(seg) if seg else ">=0")
    if affected.versions:
        parts.append(", ".join(f"=={v}" for v in affected.versions))
    return " | ".join(parts) if parts else None


def _extract_evidence_quote(
    advisory: OsvAdvisory,
    matched_affected: OsvAffected | None = None,
) -> str | None:
    """Extract the grounded evidence quote for a matched entry, falling back to advisory level."""
    if matched_affected is not None and matched_affected.database_specific:
        aff_meta = matched_affected.database_specific.get("zerobom")
        if isinstance(aff_meta, dict):
            aff_quotes = aff_meta.get("evidence_quotes")
            if isinstance(aff_quotes, list) and aff_quotes and isinstance(aff_quotes[0], str):
                return aff_quotes[0]
    zb_meta = advisory.database_specific.get("zerobom")
    if isinstance(zb_meta, dict):
        quotes = zb_meta.get("evidence_quotes")
        if isinstance(quotes, list) and quotes and isinstance(quotes[0], str):
            return quotes[0]
    return None


def _build_match_result(
    advisory: OsvAdvisory,
    matched_affected: OsvAffected,
    *,
    component_identifier: str,
    eval_version: str,
    matched_via: Literal["purl", "upstream", "name_fallback"],
    sbom_source: str | None,
    asset: AssetRef | None,
) -> MatchResult:
    """Evaluate version membership and construct a :class:`MatchResult`."""
    vulnerable = is_version_affected(
        matched_affected.package.ecosystem,
        eval_version,
        matched_affected,
    )

    fixed_versions: list[str] = []
    for osv_range in matched_affected.ranges:
        for event in osv_range.events:
            if event.fixed is not None and event.fixed not in fixed_versions:
                fixed_versions.append(event.fixed)

    return MatchResult(
        advisory_id=advisory.id,
        component_purl=component_identifier,
        installed_version=eval_version,
        matched_purl=matched_affected.package.purl,
        ecosystem=matched_affected.package.ecosystem,
        is_vulnerable=vulnerable,
        matched_range=_format_affected_ranges(matched_affected),
        fixed_versions=tuple(fixed_versions),
        evidence_quote=_extract_evidence_quote(advisory, matched_affected),
        sbom_source=sbom_source,
        asset=asset,
        matched_via=matched_via,
    )


def _match_canonical_purl_against_advisory(
    advisory: OsvAdvisory,
    *,
    component_canonical: str,
    component_identifier: str,
    installed_version: str,
    comp_distro: str | None,
    upstream_name: str | None,
    upstream_version: str | None,
    sbom_source: str | None,
    asset: AssetRef | None,
) -> MatchResult | None:
    """Match a canonical PURL (and optional upstream source PURL) against an advisory."""
    compatible_entries: list[tuple[OsvAffected, str]] = []
    for affected in advisory.affected:
        _, adv_release = parse_osv_ecosystem(affected.package.ecosystem)
        if not is_distro_compatible(adv_release, comp_distro):
            continue
        affected_canonical, _ = _canonicalize_component_purl(affected.package.purl)
        compatible_entries.append((affected, affected_canonical))

    # Pass 1: Direct canonical PURL match takes precedence over upstream fallback.
    # Evaluate all matching entries so a vulnerable branch is not shadowed by an earlier
    # non-vulnerable branch for the same package.
    direct_fallback: MatchResult | None = None
    for affected, affected_canonical in compatible_entries:
        if affected_canonical == component_canonical:
            result = _build_match_result(
                advisory,
                affected,
                component_identifier=component_identifier,
                eval_version=installed_version,
                matched_via="purl",
                sbom_source=sbom_source,
                asset=asset,
            )
            if result.is_vulnerable:
                return result
            if direct_fallback is None:
                direct_fallback = result
    if direct_fallback is not None:
        return direct_fallback

    # Pass 2: Upstream source package match (e.g., Debian/Alpine binary -> source advisory).
    if upstream_name is not None:
        upstream_canonical = _build_upstream_canonical(component_canonical, upstream_name)
        if upstream_canonical is not None:
            upstream_fallback: MatchResult | None = None
            for affected, affected_canonical in compatible_entries:
                if affected_canonical == upstream_canonical:
                    result = _build_match_result(
                        advisory,
                        affected,
                        component_identifier=component_identifier,
                        eval_version=upstream_version or installed_version,
                        matched_via="upstream",
                        sbom_source=sbom_source,
                        asset=asset,
                    )
                    if result.is_vulnerable:
                        return result
                    if upstream_fallback is None:
                        upstream_fallback = result
            if upstream_fallback is not None:
                return upstream_fallback

    return None


def evaluate_component_against_advisory(
    advisory: OsvAdvisory,
    component_purl: str,
    installed_version: str | None = None,
    *,
    sbom_source: str | None = None,
    asset: AssetRef | None = None,
) -> MatchResult | None:
    """Evaluate an SBOM component PURL and version against a compiled :class:`OsvAdvisory`.

    Supports distro release compatibility filtering via ``?distro=`` qualifiers and source
    package matching via ``?upstream=`` qualifiers.

    Args:
        advisory: Compiled OSV advisory.
        component_purl: SBOM component Package URL (may embed ``@version`` and qualifiers).
        installed_version: Explicit installed version overriding ``component_purl`` version.
        sbom_source: Optional source SBOM filename or inventory identifier for reporting.
        asset: Optional cloud-agnostic :class:`AssetRef` associated with the component.

    Returns:
        A :class:`MatchResult` if the package matches an affected entry (with ``is_vulnerable``
        set deterministically), or ``None`` if the advisory does not apply to this package.

    Raises:
        ValueError: If no version is supplied via ``installed_version`` or ``component_purl``,
            or if the PURL/version is malformed.
    """
    component_canonical, purl_version = _canonicalize_component_purl(component_purl)
    version_str = installed_version if installed_version is not None else purl_version
    if not version_str:
        raise ValueError("installed_version must be supplied or embedded in component_purl")

    comp_distro, upstream_name, upstream_version = extract_purl_os_qualifiers(component_purl)
    return _match_canonical_purl_against_advisory(
        advisory,
        component_canonical=component_canonical,
        component_identifier=component_purl,
        installed_version=version_str,
        comp_distro=comp_distro,
        upstream_name=upstream_name,
        upstream_version=upstream_version,
        sbom_source=sbom_source,
        asset=asset,
    )


def _name_fallback_matches(
    component: InventoryComponent,
    affected: OsvAffected,
) -> bool:
    """Check whether a PURL-less component safely matches an OSV affected package by name."""
    raw_name = component.name.strip()
    lowered_name = raw_name.lower()
    if len(raw_name) <= 1:
        return False

    affected_purl = PackageURL.from_string(affected.package.purl)
    if component.ecosystem is not None:
        comp_type, _ = normalize_ecosystem(component.ecosystem)
        if comp_type is not None and comp_type != affected_purl.type:
            return False

    if affected_purl.type in {"maven", "npm", "golang", "composer"} and affected_purl.namespace:
        affected_ns = affected_purl.namespace.lower()
        affected_pkg = affected_purl.name.lower()
        if component.namespace is not None:
            # Explicit namespace qualifies even blocklisted artifact names (e.g. com.acme:utils).
            return (
                component.namespace.strip().lower() == affected_ns and lowered_name == affected_pkg
            )
        # Without component.namespace, require qualified coordinates in the raw name itself.
        qualified_names = {
            affected.package.name.lower(),
            f"{affected_ns}/{affected_pkg}",
            f"{affected_ns}:{affected_pkg}",
        }
        return lowered_name in qualified_names

    if lowered_name in GENERIC_PACKAGE_BLOCKLIST:
        return False
    if (
        lowered_name in REGISTRY_ONLY_GENERIC_BLOCKLIST
        and affected_purl.type not in _RUNTIME_FRIENDLY_PURL_TYPES
    ):
        return False

    if affected_purl.type == "pypi":
        return _normalize_pep503(raw_name) == affected_purl.name.lower()

    if affected_purl.type in {"maven", "npm", "golang", "composer"}:
        if component.namespace is not None:
            return (
                component.namespace.strip().lower() == (affected_purl.namespace or "").lower()
                and lowered_name == affected_purl.name.lower()
            )
        return (
            lowered_name == affected.package.name.lower()
            or lowered_name == affected_purl.name.lower()
        )

    return lowered_name == affected_purl.name.lower()


def evaluate_inventory_component(
    advisory: OsvAdvisory,
    component: InventoryComponent,
) -> MatchResult | None:
    """Evaluate a normalized :class:`InventoryComponent` against a compiled :class:`OsvAdvisory`.

    Prioritizes raw PURL matching (preserving qualifiers), then pre-resolved canonical PURL,
    and finally safe non-generic name fallback for PURL-less SBOM entries.

    Args:
        advisory: Compiled OSV advisory.
        component: Normalized inventory component returned by an inventory backend.

    Returns:
        A :class:`MatchResult` if the component matches an affected package, else ``None``.
    """
    source = component.asset.location or component.asset.asset_id

    if component.purl is not None:
        comp_distro, upstream_name, upstream_version = extract_purl_os_qualifiers(component.purl)
        component_canonical, _ = _canonicalize_component_purl(component.purl)
        return _match_canonical_purl_against_advisory(
            advisory,
            component_canonical=component_canonical,
            component_identifier=component.purl,
            installed_version=component.version,
            comp_distro=comp_distro or component.distro_qualifier,
            upstream_name=upstream_name or component.upstream_package,
            upstream_version=upstream_version or component.upstream_version,
            sbom_source=source,
            asset=component.asset,
        )

    if component.canonical_purl is not None:
        return _match_canonical_purl_against_advisory(
            advisory,
            component_canonical=component.canonical_purl,
            component_identifier=component.canonical_purl,
            installed_version=component.version,
            comp_distro=component.distro_qualifier,
            upstream_name=component.upstream_package,
            upstream_version=component.upstream_version,
            sbom_source=source,
            asset=component.asset,
        )

    # PURL-less SBOM fallback: refuse generic names and verify distro/version safety.
    # Evaluate all matching affected entries so multi-ecosystem or multi-branch advisories
    # do not shadow a vulnerable match behind an earlier non-vulnerable branch.
    fallback_result: MatchResult | None = None
    for affected in advisory.affected:
        _, adv_release = parse_osv_ecosystem(affected.package.ecosystem)
        if not is_distro_compatible(adv_release, component.distro_qualifier):
            continue
        if not _name_fallback_matches(component, affected):
            continue
        try:
            result = _build_match_result(
                advisory,
                affected,
                component_identifier=f"name:{component.name}@{component.version}",
                eval_version=component.version,
                matched_via="name_fallback",
                sbom_source=source,
                asset=component.asset,
            )
        except ValueError:
            # Skip cross-ecosystem version syntax mismatches during untyped fallback scans.
            continue
        if result.is_vulnerable:
            return result
        if fallback_result is None:
            fallback_result = result

    return fallback_result
