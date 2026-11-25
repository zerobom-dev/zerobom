"""Two-stage verbatim quote grounding verification.

This module enforces zero-trust grounding between extracted advisory claims and the raw
source article text:

1. **Stage 1 (Article Grounding):** Verifies that ``evidence_quote`` appears verbatim—or after
   deterministic NFKC, quote/dash, and whitespace normalization—inside the raw article body,
   defending against fabricated LLM quotes.
2. **Stage 2 (Anti-Bait-and-Switch Token Check):** Confirms that both a candidate package name
   token and at least one non-``"0"`` claimed version token appear inside the matched quote
   itself, preventing prompt-injected or mismatched pairings where a real sentence is paired
   with an unrelated package or version.

All untrusted tokens passed to regular-expression boundary searches are escaped via
``re.escape`` to eliminate regex-injection and catastrophic-backtracking risks.
"""

from __future__ import annotations

import re
import unicodedata

from zerobom.models import (
    ExtractedPackageClaim,
    GroundingMatchType,
    GroundingResult,
    GroundingStatus,
)

MIN_QUOTE_LENGTH = 15
MIN_QUOTE_TOKENS = 3
MIN_LIST_ITEM_LENGTH = 8
MIN_LIST_ITEM_TOKENS = 2
MAX_COLON_LIST_GAP_CHARS = 400
_TRAILING_QUOTE_PUNCT = ".,;:"
# Block cross-sentence prose splicing while permitting inline/bulleted list delimiters.
_PROSE_SENTENCE_BREAK_RE = re.compile(r"[.?!]\s+(?![-*\u2022])")

# Reject negation/non-impact phrases between a colon heading and a spliced list entry.
_COLON_LIST_NEGATION_RE = re.compile(
    r"\b(?:unaffected|not\s+affected|no\s+impact|not\s+vulnerable|latest\s+stable)\b",
    re.IGNORECASE,
)

# Quote-polarity guards rejecting inverted malicious/through/copyright claims as "fixed".
_FIX_PHRASING_RE = re.compile(
    r"\b(?:fix(?:ed|es)?|patch(?:ed|es)?|resolv(?:ed|es)|address(?:ed|es)|remediat(?:ed|es)|"
    r"mitigat(?:ed|es)|upgrade\s+to|update\s+to|prior\s+to|before|earlier\s+than|below|"
    r"newer\s+than|security\s+(?:fix|release)|backport(?:ed|s)?|hot[- ]?patch(?:ed)?)\b",
    re.IGNORECASE,
)
_MALICIOUS_COMPROMISE_PHRASE_RE = re.compile(
    r"\b(?:malicious\s+(?:package|packages|version|versions|release|releases|npm|pypi|"
    r"nuget|crate|postinstall|workflow)|postinstall\s+malware|"
    r"published\s+by\s+(?:the\s+)?compromised|"
    r"compromised\s+(?:(?:npm|pypi|python|nuget|cargo|rust|gem|ruby|go|golang|"
    r"maven|composer|php|github)\s+)?(?:account|maintainer|package|packages|version|"
    r"versions|release|releases|module|crate|gem|library)|remains\s+listed|"
    r"obfuscated\s+dropper|remote[- ]code\s+loader|secret\s+stealer|trojanized|"
    r"contain\s+(?:the\s+)?payload|as\s+compromised)\b",
    re.IGNORECASE,
)
_VULN_CONTEXT_PHRASE_RE = re.compile(
    r"\b(?:vulnerab(?:le|ility|ilities)|rce|code\s+execution|ssrf|xss|overflow|"
    r"deserialization|injection|traversal|bypass|privilege\s+escalation|denial[- ]of[- ]service|"
    r"memory\s+corruption|backdoor|malicious|compromised|cve-\d{4}-\d{4,7}|"
    r"fixed|patched|upgrade|affected)\b",
    re.IGNORECASE,
)
_DISTRO_MENTION_RE = re.compile(
    r"\b(?:debian|ubuntu|redhat|red\s+hat|rhel|cloudlinux|eurolinux|alpine|suse|sles|"
    r"opensuse|fedora|centos|rocky|almalinux|oraclelinux|oracle\s+linux|amzn|"
    r"amazon\s+linux|azurelinux|wolfi|chainguard|buster|bullseye|bookworm|trixie|"
    r"focal|jammy|noble|rpm|deb|apk|dpkg)\b",
    re.IGNORECASE,
)
_DISTRO_VERSION_MARKER_RE = re.compile(
    r"(?:\+deb\d+|ubuntu|\.el\d+|\.fc\d+|-r\d+\b|tuxcare|lve)",
    re.IGNORECASE,
)

# Strip invisible formatting code points (zero-width, soft hyphen, word joiner, BiDi) that
# break exact substring matching in scraped HTML.
_ZERO_WIDTH_RE = re.compile(r"[\u00ad\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]")
_WHITESPACE_RE = re.compile(r"\s+")
_CHAR_NORMALIZATION = str.maketrans(
    {
        "\u2018": "'",
        "\u2019": "'",
        "\u2032": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2033": '"',
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": "-",
        "\u2014": "-",
        "\u2212": "-",
    }
)

_VERSION_TOKEN_RE = re.compile(r"(?<![a-zA-Z0-9])v?(?:\d+[:!])?\d+(?:\.\d+)+[a-zA-Z0-9.+~_-]*")

_ECOSYSTEM_PREFIX_RE = re.compile(
    r"^(?:the\s+)?(?:python|pypi|pip|node(?:\.js)?|nodejs|npm|javascript|js|"
    r"java|maven|go|golang|debian|ubuntu|apt|dpkg|redhat|rhel|rpm|fedora|cloudlinux|"
    r"suse|sles|opensuse|oraclelinux|amazonlinux|azurelinux|alpine|apk|wolfi|"
    r"chainguard|rust|cargo|crates\.io|ruby|rubygems|gem|php|composer|packagist|"
    r"nuget|\.net|dotnet|generic)\s+",
    re.IGNORECASE,
)
_WRAPPER_WORD_RE = re.compile(
    r"^(?:the|package|library|lib|module|crate|gem|component)\s+",
    re.IGNORECASE,
)


def normalize_text(text: str) -> str:
    """Normalize text for deterministic quote matching.

    Applies Unicode NFKC normalization, strips zero-width characters, folds typographic quotes
    and dashes into ASCII equivalents, collapses whitespace, and case-folds.

    Args:
        text: Untrusted article or quote text.

    Returns:
        Normalized lowercase string suitable for deterministic substring lookup.
    """
    normalized = unicodedata.normalize("NFKC", text)
    normalized = _ZERO_WIDTH_RE.sub("", normalized)
    normalized = normalized.translate(_CHAR_NORMALIZATION)
    normalized = _WHITESPACE_RE.sub(" ", normalized).strip().casefold()
    return normalized


def _strip_package_wrappers(raw_name: str) -> str:
    """Strip natural-language wrapper words and leading ecosystem prefixes iteratively."""
    cleaned = raw_name.strip()
    changed = True
    while changed:
        changed = False
        for pattern in (_WRAPPER_WORD_RE, _ECOSYSTEM_PREFIX_RE):
            updated = pattern.sub("", cleaned, count=1).strip()
            if updated != cleaned:
                cleaned = updated
                changed = True
    return cleaned


def _is_implied_branch_origin(introduced: str, upper_bound: str | None) -> bool:
    """Return True when ``introduced`` is an implied ``.0`` branch origin for ``upper_bound``."""
    if upper_bound is None:
        return False
    intro_clean = introduced.strip().lstrip("vV")
    upper_clean = upper_bound.strip().lstrip("vV")
    if not intro_clean or not upper_clean or intro_clean.casefold() == upper_clean.casefold():
        return False
    intro_parts = intro_clean.split(".")
    if len(intro_parts) < 2 or not all(part.isdigit() for part in intro_parts):
        return False
    if len(intro_parts) >= 3 and intro_parts[-1] == "0":
        branch_prefix = ".".join(intro_parts[:-1]) + "."
        if upper_clean.startswith(branch_prefix):
            return True
    if all(part == "0" for part in intro_parts[1:]):
        major_prefix = f"{intro_parts[0]}."
        if upper_clean.startswith(major_prefix):
            return True
    return False


def extract_claim_version_tokens(claim: ExtractedPackageClaim) -> tuple[str, ...]:
    """Extract non-``"0"`` version tokens from a claim's structured constraints.

    Args:
        claim: Extracted package claim containing zero or more version constraints.

    Returns:
        Deduplicated tuple of concrete version strings (excluding the OSV ``"0"`` sentinel).
    """
    tokens: list[str] = []
    seen: set[str] = set()

    def _add(token: str, *, allow_zero_sentinel: bool = False) -> None:
        cleaned = token.strip().rstrip(".,;:)")
        # Exclude OSV origin sentinel "0" on introduced bounds only; fixed="0" must be grounded.
        if not cleaned or (allow_zero_sentinel and cleaned == "0"):
            return
        key = cleaned.casefold()
        if key not in seen:
            seen.add(key)
            tokens.append(cleaned)

    for constraint in claim.version_constraints:
        upper = constraint.fixed or constraint.last_affected
        skip_implied_intro = constraint.introduced is not None and _is_implied_branch_origin(
            constraint.introduced, upper
        )
        implied_intro_key = (
            constraint.introduced.strip().rstrip(".,;:)").casefold()
            if skip_implied_intro and constraint.introduced is not None
            else None
        )
        if constraint.introduced is not None and not skip_implied_intro:
            _add(constraint.introduced, allow_zero_sentinel=True)
        for bound in (
            constraint.fixed,
            constraint.last_affected,
            constraint.exact,
        ):
            if bound is not None:
                _add(bound)
        if constraint.raw_specifier is not None:
            for match in _VERSION_TOKEN_RE.findall(constraint.raw_specifier):
                match_key = match.strip().rstrip(".,;:)").casefold()
                if implied_intro_key is not None and (
                    match_key == implied_intro_key
                    or match_key.lstrip("v") == implied_intro_key.lstrip("v")
                ):
                    continue
                _add(match)

    return tuple(tokens)


def extract_package_match_candidates(
    raw_package_name: str,
    canonical_package_name: str | None = None,
) -> tuple[str, ...]:
    """Build normalized package name candidates for Stage 2 quote token verification.

    Args:
        raw_package_name: Raw package identifier or natural-language name from the claim.
        canonical_package_name: Optional canonical PURL ``name`` segment from PURL resolution.

    Returns:
        Deduplicated tuple of normalized package name variants (including delimiter aliases).
    """
    seeds: list[str] = []
    if canonical_package_name:
        seeds.append(canonical_package_name)
    seeds.append(raw_package_name)

    stripped = _strip_package_wrappers(raw_package_name)
    if stripped and stripped != raw_package_name:
        seeds.append(stripped)

    expanded: list[str] = []
    for seed in seeds:
        norm = normalize_text(seed)
        if not norm:
            continue
        expanded.append(norm)

        if norm.startswith("pkg:"):
            # Extract leaf package name when raw_package_name was already formatted as a PURL.
            without_qualifiers = norm.split("?", 1)[0].split("#", 1)[0].split("@", 1)[0]
            parts = without_qualifiers[4:].split("/")
            if parts:
                expanded.append(parts[-1])
            continue

        # Maven group:artifact -> also allow artifact alone as prose often drops groupId.
        if ":" in norm:
            artifact = norm.split(":", 1)[1].strip()
            if artifact:
                expanded.append(artifact)

        # Scoped npm (@scope/pkg) or Go/Maven path (github.com/org/repo) -> allow leaf name.
        if "/" in norm:
            leaf = norm.rsplit("/", 1)[-1].strip()
            if leaf:
                expanded.append(leaf)

    candidates: list[str] = []
    seen: set[str] = set()
    for item in expanded:
        variants = {
            item,
            item.replace("::", "-"),
            item.replace("::", "_"),
            item.replace("::", " "),
            item.replace("-", "::"),
            item.replace("-", "_"),
            item.replace("_", "-"),
            item.replace("-", " "),
            item.replace("_", " "),
        }
        for variant in variants:
            cleaned = _WHITESPACE_RE.sub(" ", variant).strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                candidates.append(cleaned)

    return tuple(candidates)


def _contains_token_boundary(haystack: str, needle: str) -> bool:
    """Match ``needle`` inside ``haystack`` with alphanumeric boundaries (regex-escaped)."""
    # re.escape neutralizes regex metacharacters from untrusted package or version tokens.
    pattern = rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])"
    return re.search(pattern, haystack) is not None


def _version_matches_quote(
    norm_quote: str,
    version_token: str,
    package_candidates: tuple[str, ...] = (),
) -> bool:
    """Check whether a claimed version token (including NVR or ``v`` variants) matches."""
    norm_token = normalize_text(version_token)
    if not norm_token:
        return False

    variants: list[str] = [norm_token]
    if norm_token.startswith("v") and len(norm_token) > 1:
        variants.append(norm_token[1:])
    else:
        variants.append(f"v{norm_token}")

    for cand in package_candidates:
        pkg_prefix = f"{cand.replace(' ', '-')}-"
        if norm_token.startswith(pkg_prefix):
            bare = norm_token[len(pkg_prefix) :]
            if bare and bare[0].isdigit():
                variants.append(bare)
                variants.append(f"v{bare}")

    return any(_contains_token_boundary(norm_quote, variant) for variant in variants)


def _find_boundary_safe_substring(
    haystack: str,
    needle: str,
    *,
    start: int = 0,
    max_start: int | None = None,
) -> int:
    """Locate ``needle`` in ``haystack`` ending on a non-token-continuation boundary.

    Prevents truncated version prefixes or trailing-punctuation fallback matches from
    matching a prefix of a longer version or identifier (for example, matching ``8.2.3`` or
    ``8.2.3.`` against ``8.2.35`` or ``8.2.3.1``).

    Args:
        haystack: Full or normalized article body text.
        needle: Exact, normalized, or trailing-punctuation-trimmed quote string.
        start: Inclusive starting character index in ``haystack`` for searching.
        max_start: Optional maximum inclusive starting index permitted for matches.

    Returns:
        Lowest starting index of a boundary-safe match, or ``-1`` if none exists.
    """
    if not needle:
        return -1

    cursor = start
    haystack_len = len(haystack)
    needle_len = len(needle)
    first_ch = needle[0]
    starts_with_alnum = first_ch.isalnum()
    starts_with_token_sep = first_ch in ".-_+" and needle_len >= 2 and needle[1].isalnum()
    last_ch = needle[-1]
    ends_with_alnum = last_ch.isalnum()
    ends_with_token_sep = last_ch in ".-_+" and needle_len >= 2 and needle[-2].isalnum()
    while True:
        idx = haystack.find(needle, cursor)
        if idx == -1 or (max_start is not None and idx > max_start):
            return -1
        # Mirror right-boundary protection on the left edge so truncated numeric or package
        # prefixes (e.g. "2.30.0" in "12.30.0" or "requests" in "myrequests") fail closed.
        if idx > 0:
            prev_ch = haystack[idx - 1]
            if starts_with_alnum:
                left_continuation = prev_ch.isalnum() or (
                    prev_ch in ".-_+" and idx >= 2 and haystack[idx - 2].isalnum()
                )
            elif starts_with_token_sep:
                left_continuation = prev_ch.isalnum()
            else:
                left_continuation = False
            if left_continuation:
                cursor = idx + 1
                continue
        end = idx + needle_len
        if end == haystack_len:
            return idx
        next_ch = haystack[end]
        # Reject exact/normalized/trimmed slices that bisect a longer version or identifier.
        if ends_with_alnum:
            is_continuation = next_ch.isalnum() or (
                next_ch in ".-_+" and end + 1 < haystack_len and haystack[end + 1].isalnum()
            )
        elif ends_with_token_sep:
            is_continuation = next_ch.isalnum()
        else:
            is_continuation = False
        if not is_continuation:
            return idx
        cursor = idx + 1


def _match_colon_list_quote(
    norm_body: str,
    norm_quote: str,
    *,
    min_prefix_length: int,
    min_prefix_tokens: int,
) -> tuple[tuple[int, int], str] | None:
    """Verify a quote combining a list heading ending in ``:`` with one bounded list item.

    Supports both inline comma/semicolon lists and bulleted lists where the extractor
    pairs the list-introducing clause with a later entry in the same list, while blocking
    cross-sentence prose splicing, distant sections, short headings, bare versions, and
    truncated version tokens.

    Args:
        norm_body: Normalized full article body text.
        norm_quote: Normalized extracted quote text.
        min_prefix_length: Minimum normalized character length for the heading prefix.
        min_prefix_tokens: Minimum whitespace-delimited token count for the heading prefix.

    Returns:
        ``((span_start, span_end), matched_quote)`` omitting intervening skipped items so
        Stage 2 validates claimed versions against the cited entry itself, or ``None``.
    """
    search_pos = 0
    while True:
        colon_pos = norm_quote.find(": ", search_pos)
        if colon_pos == -1:
            return None
        search_pos = colon_pos + 2

        prefix = norm_quote[: colon_pos + 1].strip()
        if len(prefix) < min_prefix_length or len(prefix.split()) < min_prefix_tokens:
            continue

        raw_suffix = norm_quote[colon_pos + 2 :].strip()
        suffix_candidates: list[str] = []
        trimmed_suffix = raw_suffix.rstrip(_TRAILING_QUOTE_PUNCT)
        for cand in (raw_suffix, trimmed_suffix):
            if (
                cand
                and cand not in suffix_candidates
                and len(cand) >= MIN_LIST_ITEM_LENGTH
                and len(cand.split()) >= MIN_LIST_ITEM_TOKENS
            ):
                suffix_candidates.append(cand)
        if not suffix_candidates:
            continue

        p_start = 0
        prefix_len = len(prefix)
        while True:
            p_idx = norm_body.find(prefix, p_start)
            if p_idx == -1:
                break
            p_start = p_idx + 1
            if p_idx > 0 and norm_body[p_idx - 1].isalnum():
                continue

            p_end = p_idx + prefix_len
            for cand_suffix in suffix_candidates:
                s_idx = _find_boundary_safe_substring(
                    norm_body,
                    cand_suffix,
                    start=p_end,
                    max_start=p_end + MAX_COLON_LIST_GAP_CHARS,
                )
                if s_idx == -1:
                    continue
                gap = norm_body[p_end:s_idx]
                if _PROSE_SENTENCE_BREAK_RE.search(gap) is not None:
                    continue
                if (
                    _COLON_LIST_NEGATION_RE.search(gap) is not None
                    or _COLON_LIST_NEGATION_RE.search(cand_suffix) is not None
                ):
                    continue
                return (p_idx, s_idx + len(cand_suffix)), f"{prefix} {cand_suffix}"


def _match_single_quote_stage1(
    article_body: str,
    quote: str,
    *,
    norm_body: str | None,
    min_quote_length: int,
    min_quote_tokens: int,
    is_primary: bool,
) -> tuple[bool, GroundingMatchType, tuple[int, int] | None, str, str | None, str | None]:
    """Validate length thresholds and Stage 1 article substring presence for one quote."""
    norm_quote = normalize_text(quote)
    quote_tokens = norm_quote.split() if norm_quote else []
    label = "Evidence quote" if is_primary else "Supporting quote"

    if not norm_quote:
        return (
            False,
            GroundingMatchType.NONE,
            None,
            norm_quote,
            norm_body,
            f"{label} is empty.",
        )

    if len(norm_quote) < min_quote_length or len(quote_tokens) < min_quote_tokens:
        return (
            False,
            GroundingMatchType.NONE,
            None,
            norm_quote,
            norm_body,
            (
                f"{label} is too short (chars={len(norm_quote)}<{min_quote_length} "
                f"or tokens={len(quote_tokens)}<{min_quote_tokens})."
            ),
        )

    exact_idx = _find_boundary_safe_substring(article_body, quote)
    if exact_idx != -1:
        return (
            True,
            GroundingMatchType.EXACT,
            (exact_idx, exact_idx + len(quote)),
            norm_quote,
            norm_body,
            None,
        )

    resolved_norm_body = norm_body if norm_body is not None else normalize_text(article_body)
    norm_idx = _find_boundary_safe_substring(resolved_norm_body, norm_quote)
    if norm_idx != -1:
        return (
            True,
            GroundingMatchType.NORMALIZED,
            (norm_idx, norm_idx + len(norm_quote)),
            norm_quote,
            resolved_norm_body,
            None,
        )

    trimmed_quote = norm_quote.rstrip(_TRAILING_QUOTE_PUNCT)
    if (
        trimmed_quote != norm_quote
        and len(trimmed_quote) >= min_quote_length
        and len(trimmed_quote.split()) >= min_quote_tokens
    ):
        trimmed_idx = _find_boundary_safe_substring(resolved_norm_body, trimmed_quote)
        if trimmed_idx != -1:
            return (
                True,
                GroundingMatchType.NORMALIZED,
                (trimmed_idx, trimmed_idx + len(trimmed_quote)),
                trimmed_quote,
                resolved_norm_body,
                None,
            )

    colon_list_match = _match_colon_list_quote(
        resolved_norm_body,
        norm_quote,
        min_prefix_length=min_quote_length,
        min_prefix_tokens=min_quote_tokens,
    )
    if colon_list_match is not None:
        matched_span, matched_norm_quote = colon_list_match
        return (
            True,
            GroundingMatchType.NORMALIZED,
            matched_span,
            matched_norm_quote,
            resolved_norm_body,
            None,
        )

    return (
        False,
        GroundingMatchType.NONE,
        None,
        norm_quote,
        resolved_norm_body,
        f"{label} does not appear in article body.",
    )


def verify_quote_grounding(
    article_body: str,
    claim: ExtractedPackageClaim,
    *,
    canonical_package_name: str | None = None,
    min_quote_length: int = MIN_QUOTE_LENGTH,
    min_quote_tokens: int = MIN_QUOTE_TOKENS,
) -> GroundingResult:
    """Verify extracted evidence quote(s) against the raw article text in two stages.

    Checks ``claim.evidence_quote`` and every entry in ``claim.supporting_quotes``. All quotes
    must pass Stage 1 substring grounding, and at least one single verified quote must mention
    both a package token and a claimed version token (preventing cross-paragraph bait-and-switch).

    Args:
        article_body: Raw plain-text body of the ingested article.
        claim: Extracted package claim containing ``evidence_quote``, optional
            ``supporting_quotes``, and constraints.
        canonical_package_name: Optional canonical PURL ``name`` to broaden valid aliases.
        min_quote_length: Minimum normalized character count required to prevent trivial matches.
        min_quote_tokens: Minimum whitespace-delimited word count required in each quote.

    Returns:
        A :class:`GroundingResult` classifying the claim as ``VERIFIED``,
        ``QUOTE_ONLY_WEAK``, or ``UNGROUNDED``.

    Raises:
        ValueError: If ``min_quote_length < 1`` or ``min_quote_tokens < 1``.
    """
    if min_quote_length < 1:
        raise ValueError("min_quote_length must be >= 1")
    if min_quote_tokens < 1:
        raise ValueError("min_quote_tokens must be >= 1")

    all_quotes = (claim.evidence_quote, *claim.supporting_quotes)
    norm_body: str | None = None
    norm_quotes: list[str] = []
    primary_span: tuple[int, int] | None = None
    all_exact = True

    for idx, quote in enumerate(all_quotes):
        ok, match_type, span, norm_q, norm_body, err_reason = _match_single_quote_stage1(
            article_body,
            quote,
            norm_body=norm_body,
            min_quote_length=min_quote_length,
            min_quote_tokens=min_quote_tokens,
            is_primary=(idx == 0),
        )
        if not ok:
            return GroundingResult(
                status=GroundingStatus.UNGROUNDED,
                match_type=GroundingMatchType.NONE,
                quote_found_in_article=False,
                package_token_found=False,
                version_tokens_found=False,
                matched_span=None,
                reasons=(err_reason or "Quote failed grounding.",),
            )
        if idx == 0:
            primary_span = span
        if match_type != GroundingMatchType.EXACT:
            all_exact = False
        norm_quotes.append(norm_q)

    overall_match_type = GroundingMatchType.EXACT if all_exact else GroundingMatchType.NORMALIZED

    # Stage 2: Anti-bait-and-switch check requiring package + version co-occurrence in at least
    # one single verified quote (supporting context quotes only need Stage 1 article grounding).
    candidates = extract_package_match_candidates(
        claim.raw_package_name,
        canonical_package_name=canonical_package_name,
    )
    version_tokens = extract_claim_version_tokens(claim)

    per_quote_flags: list[tuple[bool, bool]] = []
    for norm_q in norm_quotes:
        has_pkg = any(_contains_token_boundary(norm_q, cand) for cand in candidates)
        has_ver = (
            True
            if not version_tokens
            else any(_version_matches_quote(norm_q, token, candidates) for token in version_tokens)
        )
        per_quote_flags.append((has_pkg, has_ver))

    package_token_found = any(has_pkg for has_pkg, _ in per_quote_flags)
    missing_versions = tuple(
        token
        for token in version_tokens
        if not any(_version_matches_quote(norm_q, token, candidates) for norm_q in norm_quotes)
    )
    any_version_found = (
        True if not version_tokens else any(has_ver for _, has_ver in per_quote_flags)
    )
    version_tokens_found = True if not version_tokens else not missing_versions
    has_cooccurring_quote = any(has_pkg and has_ver for has_pkg, has_ver in per_quote_flags)

    if has_cooccurring_quote and not missing_versions:
        return GroundingResult(
            status=GroundingStatus.VERIFIED,
            match_type=overall_match_type,
            quote_found_in_article=True,
            package_token_found=True,
            version_tokens_found=True,
            matched_span=primary_span,
            reasons=(),
        )

    reasons: list[str] = []
    if not package_token_found:
        reasons.append(
            f"Quote matched article text but does not mention package '{claim.raw_package_name}'."
        )
    if not any_version_found:
        reasons.append(
            "Quote matched article text but does not contain any claimed version token "
            f"({', '.join(version_tokens)})."
        )
    elif missing_versions:
        reasons.append(
            "Quote matched article text but is missing claimed version token(s) "
            f"({', '.join(missing_versions)})."
        )
    if package_token_found and any_version_found and not has_cooccurring_quote:
        reasons.append(
            "Package name and version tokens were split across separate quotes without "
            "co-occurring in any single verified quote."
        )

    return GroundingResult(
        status=GroundingStatus.QUOTE_ONLY_WEAK,
        match_type=overall_match_type,
        quote_found_in_article=True,
        package_token_found=package_token_found,
        version_tokens_found=version_tokens_found,
        matched_span=primary_span,
        reasons=tuple(reasons),
    )


def _quote_has_explicit_fix_for_version(norm_quote: str, version_token: str) -> bool:
    """Return True if ``norm_quote`` binds exclusive/fix phrasing directly to ``version_token``."""
    bare = version_token[1:] if version_token.lower().startswith("v") else version_token
    escaped = re.escape(normalize_text(bare))
    ver_pat = rf"(?<![a-z0-9.])v?{escaped}(?![a-z0-9])"
    exclusive_pattern = re.compile(
        rf"(?:\b(?:prior\s+to|before|earlier\s+than|fixed\s+in|patched\s+in|"
        rf"resolved\s+in|upgrade\s+to|update\s+to|fixed\s+release)\s+{ver_pat}|<\s*{ver_pat})",
        re.IGNORECASE,
    )
    return exclusive_pattern.search(norm_quote) is not None


def check_quote_polarity(claim: ExtractedPackageClaim) -> tuple[bool, tuple[str, ...]]:
    """Verify that quote semantics align with claimed ``fixed`` bounds and vulnerability context.

    Catches common LLM inversions where tool copyright banners, compromised/malicious package
    versions, or inclusive ``through <ver>`` phrases are mislabeled as ``fixed``.

    Args:
        claim: Extracted package claim to validate deterministically.

    Returns:
        Tuple ``(is_consistent, diagnostic_reasons)``.
    """
    combined = normalize_text(" ".join((claim.evidence_quote, *claim.supporting_quotes)))
    if not combined:
        return True, ()

    reasons: list[str] = []

    # 1) Reject copyright/tool-banner quotes that lack any vulnerability/fix context.
    if not _VULN_CONTEXT_PHRASE_RE.search(combined) and (
        re.search(r"\bcopyright\b", combined) is not None
    ):
        reasons.append(
            "Evidence quote appears to be a copyright or banner notice without vulnerability "
            "context."
        )

    has_fix_phrasing = _FIX_PHRASING_RE.search(combined) is not None
    has_malicious_phrase = _MALICIOUS_COMPROMISE_PHRASE_RE.search(combined) is not None

    for constraint in claim.version_constraints:
        if constraint.fixed is None:
            continue
        fixed_clean = normalize_text(constraint.fixed)
        bare_fixed = (
            fixed_clean[1:] if fixed_clean.startswith("v") and len(fixed_clean) > 1 else fixed_clean
        )
        escaped_fixed = re.escape(bare_fixed)
        ver_pat = rf"(?<![a-z0-9.])v?{escaped_fixed}(?![a-z0-9])"

        # 2) Malicious/compromised package wording without fix language must not claim "fixed".
        if has_malicious_phrase and not has_fix_phrasing:
            reasons.append(
                f"Claim sets fixed='{constraint.fixed}' while quote describes a compromised or "
                "malicious release without naming a fix version."
            )
            continue

        # 3) Inclusive or confirmed-vulnerable wording paired with `fixed` -> polarity conflict.
        inclusive_re = re.compile(
            rf"(?:\b(?:through|up\s+to\s+and\s+including)\s+{ver_pat}|"
            rf"{ver_pat}\s+and\s+(?:earlier|prior|older|below)|"
            rf"\b(?:confirmed\s+against|got\s+code\s+execution)\b[^.?!]{{0,60}}{ver_pat})",
            re.IGNORECASE,
        )
        if inclusive_re.search(combined) is not None and not _quote_has_explicit_fix_for_version(
            combined, bare_fixed
        ):
            reasons.append(
                f"Claim sets fixed='{constraint.fixed}' while quote describes it as an inclusive "
                "or confirmed-affected version."
            )

    return (len(reasons) == 0), tuple(dict.fromkeys(reasons))


def check_distro_quote_grounding(
    claim: ExtractedPackageClaim,
    *,
    ecosystem: str | None,
    namespace: str | None,
) -> tuple[bool, tuple[str, ...]]:
    """Verify OS distro package claims are anchored in distro evidence in their quotes.

    Prevents LLMs from fabricating ``deb``/``rpm``/``apk`` package claims out of upstream
    application advisories that never mention OS vendor packages.

    Args:
        claim: Extracted package claim under evaluation.
        ecosystem: Normalized PURL ecosystem type (e.g., ``"deb"``, ``"rpm"``, ``"apk"``).
        namespace: Normalized package namespace (e.g., ``"debian"``, ``"ubuntu"``).

    Returns:
        Tuple ``(is_grounded_distro, diagnostic_reasons)``.
    """
    if ecosystem not in {"deb", "rpm", "apk"}:
        return True, ()

    combined = normalize_text(" ".join((claim.evidence_quote, *claim.supporting_quotes)))
    if not combined:
        return False, ("OS distro claim has empty evidence quote.",)

    if (
        _DISTRO_MENTION_RE.search(combined) is not None
        or _DISTRO_VERSION_MARKER_RE.search(combined) is not None
    ):
        return True, ()

    if namespace:
        ns_norm = normalize_text(namespace)
        if ns_norm and _contains_token_boundary(combined, ns_norm):
            return True, ()

    return False, (
        f"OS distro claim ({ecosystem}/{namespace or 'unknown'}) lacks distro package or version "
        "evidence inside the cited quote.",
    )
