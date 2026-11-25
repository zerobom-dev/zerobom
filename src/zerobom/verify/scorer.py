"""Two-axis credibility gate and deterministic claim/advisory verification scorer.

Every extracted package claim is gated by the deterministic formula:

``composite_score = source_tier_weight * extraction_specificity``

where:

- **Axis 1 (Source Tier Weight):** ``TIER_1=1.0``, ``TIER_2=0.85``, ``UNKNOWN=0.55`` (ensuring
  untrusted/unknown blogs can never reach ``AUTO`` without human triage).
- **Axis 2 (Extraction Specificity Rubric, ``[0.0, 1.0]``):**
  - Canonical non-generic PURL: ``+0.25``
  - Version specificity: ``+0.35`` bounded valid range, ``+0.10`` unbounded valid range
  - Quote grounding: ``+0.30`` ``VERIFIED``, ``+0.15`` ``QUOTE_ONLY_WEAK``, ``+0.0``
    ``UNGROUNDED``
  - Corroboration (capped at ``+0.10``): registry ``EXISTS`` (``+0.10``) or offline/error
    baseline (``+0.05``), plus ``+0.05`` for fix commit, PoC, or CWE/alias technical context.
- **Hard Gates & Grounding Caps:** Invalid PURLs, generic blocklisted names, and registry
  ``NOT_FOUND`` responses fail closed at ``0.0`` (``DROP``). ``UNGROUNDED`` quotes cap
  specificity at ``<= 0.35`` (guaranteed ``DROP``); ``QUOTE_ONLY_WEAK`` quotes, unbounded
  version claims (no upper bound or exact release), and ``RegistryStatus.ERROR`` failures
  cap specificity at ``<= 0.70`` (maximum ``TRIAGE``, never ``AUTO``).
- **Routing Thresholds:** ``>= 0.75`` -> ``AUTO``, ``0.50 - 0.7499`` -> ``TRIAGE``,
  ``< 0.50`` -> ``DROP``.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from zerobom.models import (
    ArticleType,
    ClaimVerificationResult,
    CredibilityReport,
    ExtractedAdvisory,
    ExtractedPackageClaim,
    GroundingResult,
    GroundingStatus,
    PurlResolutionResult,
    RawArticle,
    RegistryStatus,
    RoutingDecision,
    SourceTier,
    VersionConstraint,
)
from zerobom.verify.grounding import (
    check_distro_quote_grounding,
    check_quote_polarity,
    verify_quote_grounding,
)
from zerobom.verify.osv_compiler import (
    _format_claim_osv_ecosystem,
    detect_overlapping_branch_ranges,
    validate_claim_versions,
)
from zerobom.verify.purl import RegistryChecker, resolve_purl

TIER_WEIGHTS: dict[SourceTier, float] = {
    SourceTier.TIER_1: 1.0,
    SourceTier.TIER_2: 0.85,
    SourceTier.UNKNOWN: 0.55,
}

AUTO_THRESHOLD = 0.75
TRIAGE_THRESHOLD = 0.50
UNGROUNDED_SPECIFICITY_CAP = 0.35
WEAK_GROUNDING_SPECIFICITY_CAP = 0.70
UNBOUNDED_VERSION_SPECIFICITY_CAP = 0.70
REGISTRY_ERROR_SPECIFICITY_CAP = 0.70

_CWE_ID_RE = re.compile(r"^CWE-[1-9]\d{0,4}$")
_DROP_ARTICLE_TYPES: frozenset[ArticleType] = frozenset(
    {
        ArticleType.PRODUCT_ANNOUNCEMENT,
        ArticleType.BENCHMARK_EVALUATION,
        ArticleType.OFFENSIVE_TECHNIQUE,
        ArticleType.NON_VULNERABILITY,
    }
)
_TRIAGE_ONLY_ARTICLE_TYPES: frozenset[ArticleType] = frozenset(
    {
        ArticleType.KNOWN_VULN_ANALYSIS,
        ArticleType.RESEARCH_GUIDANCE,
    }
)


def route_score(composite_score: float) -> RoutingDecision:
    """Deterministically map a composite score to ``AUTO``, ``TRIAGE``, or ``DROP``.

    Args:
        composite_score: Two-axis credibility score in ``[0.0, 1.0]``.

    Returns:
        :class:`RoutingDecision` corresponding to the threshold bands.
    """
    if composite_score >= AUTO_THRESHOLD:
        return RoutingDecision.AUTO
    if composite_score >= TRIAGE_THRESHOLD:
        return RoutingDecision.TRIAGE
    return RoutingDecision.DROP


def score_claim(
    claim: ExtractedPackageClaim,
    grounding: GroundingResult,
    purl: PurlResolutionResult,
    *,
    source_tier: SourceTier,
    has_valid_version_range: bool,
    has_bounded_version_range: bool,
    has_advisory_technical_context: bool = False,
    extra_reasons: tuple[str, ...] = (),
) -> ClaimVerificationResult:
    """Compute ``extraction_specificity``, ``composite_score``, and routing for one claim.

    Args:
        claim: Extracted package claim under evaluation.
        grounding: Output from :func:`verify_quote_grounding`.
        purl: Output from :func:`resolve_purl`.
        source_tier: Publisher credibility tier from the parent :class:`RawArticle`.
        has_valid_version_range: True when all version constraints parsed cleanly.
        has_bounded_version_range: True when at least one valid bounded or exact constraint exists.
        has_advisory_technical_context: True if the advisory includes CWEs, aliases, or refs.
        extra_reasons: Additional diagnostic messages (e.g., version parser errors).

    Returns:
        A :class:`ClaimVerificationResult` detailing scores, routing, and diagnostics.
    """
    tier_weight = TIER_WEIGHTS[source_tier]
    reasons: list[str] = list(purl.reasons) + list(grounding.reasons) + list(extra_reasons)

    # Hard-reject gate: fail closed on invalid PURL, blocked generic package, or confirmed 404.
    if (
        not purl.is_valid
        or purl.is_blocked_generic
        or purl.registry_status == RegistryStatus.NOT_FOUND
    ):
        return ClaimVerificationResult(
            claim=claim,
            grounding=grounding,
            purl=purl,
            has_valid_version_range=has_valid_version_range,
            has_bounded_version_range=has_bounded_version_range,
            extraction_specificity=0.0,
            composite_score=0.0,
            routing=RoutingDecision.DROP,
            reasons=tuple(reasons),
        )

    # Additive extraction_specificity rubric.
    specificity = 0.25  # Canonical non-generic PURL resolved

    if has_valid_version_range and has_bounded_version_range:
        specificity += 0.35
    elif has_valid_version_range:
        specificity += 0.10

    if grounding.status == GroundingStatus.VERIFIED:
        specificity += 0.30
    elif grounding.status == GroundingStatus.QUOTE_ONLY_WEAK:
        specificity += 0.15

    # Offline (SKIPPED) registry checks keep a neutral 0.05 baseline so offline runs still
    # operate cleanly while confirmed registry hits earn 0.10. Registry lookup errors fail
    # closed at 0.0 corroboration points and are capped below AUTO below.
    if purl.registry_status == RegistryStatus.EXISTS:
        registry_points = 0.10
    elif purl.registry_status == RegistryStatus.ERROR:
        registry_points = 0.0
    else:
        registry_points = 0.05
    technical_points = (
        0.05 if (claim.fix_commit_url or claim.poc_url or has_advisory_technical_context) else 0.0
    )
    specificity += min(0.10, registry_points + technical_points)

    specificity = max(0.0, min(1.0, specificity))

    # Hard grounding, unbounded-range, and registry-error caps prevent ungrounded/unbounded
    # claims or unverified registry outages from reaching AUTO alerting.
    if grounding.status == GroundingStatus.UNGROUNDED:
        specificity = min(specificity * 0.35, UNGROUNDED_SPECIFICITY_CAP)
        reasons.append("Capped specificity below DROP threshold due to ungrounded quote.")
    elif grounding.status == GroundingStatus.QUOTE_ONLY_WEAK:
        specificity = min(specificity, WEAK_GROUNDING_SPECIFICITY_CAP)
        reasons.append(
            "Capped specificity below AUTO threshold due to weak quote grounding "
            "(missing package or version tokens inside quote)."
        )

    if not has_bounded_version_range:
        specificity = min(specificity, UNBOUNDED_VERSION_SPECIFICITY_CAP)
        reasons.append(
            "Capped specificity below AUTO threshold because version constraints lack a "
            "bounded or exact fix range."
        )

    if purl.registry_status == RegistryStatus.ERROR:
        specificity = min(specificity, REGISTRY_ERROR_SPECIFICITY_CAP)
        reasons.append(
            "Capped specificity below AUTO threshold due to upstream registry lookup error."
        )

    extraction_specificity = round(specificity, 4)
    composite_score = round(tier_weight * extraction_specificity, 4)
    routing = route_score(composite_score)

    return ClaimVerificationResult(
        claim=claim,
        grounding=grounding,
        purl=purl,
        has_valid_version_range=has_valid_version_range,
        has_bounded_version_range=has_bounded_version_range,
        extraction_specificity=extraction_specificity,
        composite_score=composite_score,
        routing=routing,
        reasons=tuple(reasons),
    )


def _has_grounded_cwe(cwe_ids: Sequence[str], grounding_corpus: str) -> bool:
    """Return True if at least one valid ``CWE-*`` identifier appears in ``grounding_corpus``."""
    for cwe_id in cwe_ids:
        val = cwe_id.strip().upper()
        if not _CWE_ID_RE.match(val):
            continue
        if re.search(rf"(?<![a-z0-9]){re.escape(val.casefold())}(?![0-9])", grounding_corpus):
            return True
    return False


def _apply_triage_cap(
    claim_result: ClaimVerificationResult,
    *,
    tier_weight: float,
    extra_reasons: Sequence[str],
) -> ClaimVerificationResult:
    """Cap a non-dropped claim below the ``AUTO`` threshold with deduplicated diagnostics."""
    if not extra_reasons:
        return claim_result

    capped_specificity = round(
        min(claim_result.extraction_specificity, WEAK_GROUNDING_SPECIFICITY_CAP),
        4,
    )
    capped_composite = round(tier_weight * capped_specificity, 4)
    merged_reasons = tuple(dict.fromkeys((*claim_result.reasons, *extra_reasons)))
    return ClaimVerificationResult(
        claim=claim_result.claim,
        grounding=claim_result.grounding,
        purl=claim_result.purl,
        has_valid_version_range=claim_result.has_valid_version_range,
        has_bounded_version_range=claim_result.has_bounded_version_range,
        extraction_specificity=capped_specificity,
        composite_score=capped_composite,
        routing=route_score(capped_composite),
        reasons=merged_reasons,
    )


def verify_advisory(
    article: RawArticle,
    advisory: ExtractedAdvisory,
    *,
    registry_checker: RegistryChecker | None = None,
) -> CredibilityReport:
    """Run deterministic PURL, grounding, version, polarity, and credibility scoring.

    Args:
        article: Raw ingested security article supplying body text and source tier.
        advisory: Extracted candidate advisory containing package vulnerability claims.
        registry_checker: Optional upstream :class:`RegistryChecker` (defaults to offline ``None``).

    Returns:
        A :class:`CredibilityReport` partitioning claims into ``accepted_claims`` and
        ``dropped_claims`` along with advisory-level routing.
    """
    tier_weight = TIER_WEIGHTS[article.source_tier]

    if advisory.article_type in _DROP_ARTICLE_TYPES:
        return CredibilityReport(
            article_url=advisory.article_url,
            source_tier=article.source_tier,
            source_tier_weight=tier_weight,
            extraction_specificity=0.0,
            composite_score=0.0,
            routing=RoutingDecision.DROP,
            claim_results=(),
            accepted_claims=(),
            dropped_claims=(),
            reasons=(
                f"Dropped advisory classified as non-actionable '{advisory.article_type.value}'.",
            ),
        )

    grounding_corpus = f"{article.title}\n{article.body}\n{article.url}".casefold()
    grounded_cwe = _has_grounded_cwe(advisory.cwe_ids, grounding_corpus)
    has_tech_context = bool(
        grounded_cwe
        or advisory.references
        or advisory.known_aliases
        or any(claim.claim_aliases for claim in advisory.claims)
    )

    if not advisory.claims:
        return CredibilityReport(
            article_url=advisory.article_url,
            source_tier=article.source_tier,
            source_tier_weight=tier_weight,
            extraction_specificity=0.0,
            composite_score=0.0,
            routing=RoutingDecision.DROP,
            claim_results=(),
            accepted_claims=(),
            dropped_claims=(),
            reasons=("Advisory contains no package vulnerability claims.",),
        )

    claim_results: list[ClaimVerificationResult] = []
    for claim in advisory.claims:
        purl_res = resolve_purl(claim, registry_checker=registry_checker)
        grounding_res = verify_quote_grounding(
            article.body,
            claim,
            canonical_package_name=purl_res.name,
        )
        has_valid_ver, has_bounded_ver, ver_reasons = validate_claim_versions(
            purl_res.ecosystem,
            claim.version_constraints,
            package_name=purl_res.name,
        )
        scored = score_claim(
            claim,
            grounding_res,
            purl_res,
            source_tier=article.source_tier,
            has_valid_version_range=has_valid_ver,
            has_bounded_version_range=has_bounded_ver,
            has_advisory_technical_context=has_tech_context,
            extra_reasons=ver_reasons,
        )
        if scored.routing != RoutingDecision.DROP:
            cap_reasons: list[str] = []
            polarity_ok, polarity_reasons = check_quote_polarity(claim)
            if not polarity_ok:
                cap_reasons.extend(polarity_reasons)
            distro_ok, distro_reasons = check_distro_quote_grounding(
                claim,
                ecosystem=purl_res.ecosystem,
                namespace=purl_res.namespace,
            )
            if not distro_ok:
                cap_reasons.extend(distro_reasons)
            has_overlap, overlap_reason = detect_overlapping_branch_ranges(
                purl_res.ecosystem,
                claim.version_constraints,
                package_name=purl_res.name,
            )
            if has_overlap and overlap_reason:
                cap_reasons.append(overlap_reason)
            if (
                advisory.article_type in _TRIAGE_ONLY_ARTICLE_TYPES
                and advisory.article_type is not None
            ):
                cap_reasons.append(
                    f"Capped specificity below AUTO threshold for secondary article type "
                    f"'{advisory.article_type.value}'."
                )
            scored = _apply_triage_cap(scored, tier_weight=tier_weight, extra_reasons=cap_reasons)
        claim_results.append(scored)

    # Detect multi-claim open-origin ("introduced='0'") overlaps across separate claims targeting
    # the same canonical PURL and formatted ecosystem stream (e.g. OpenSSL 5-branch updates).
    grouped_indices: dict[tuple[str, str], list[int]] = {}
    for idx, cr in enumerate(claim_results):
        if cr.routing == RoutingDecision.DROP:
            continue
        if (
            cr.purl.canonical_purl is None
            or cr.purl.osv_ecosystem is None
            or cr.purl.ecosystem is None
        ):
            continue
        formatted_eco = _format_claim_osv_ecosystem(
            cr.purl.osv_ecosystem,
            cr.purl.ecosystem,
            cr.claim.distro_release,
        )
        grouped_indices.setdefault((cr.purl.canonical_purl, formatted_eco), []).append(idx)

    for indices in grouped_indices.values():
        if len(indices) < 2:
            continue
        first = claim_results[indices[0]]
        combined_constraints: list[VersionConstraint] = [
            constraint
            for idx in indices
            for constraint in claim_results[idx].claim.version_constraints
        ]
        has_group_overlap, group_overlap_reason = detect_overlapping_branch_ranges(
            first.purl.ecosystem,
            combined_constraints,
            package_name=first.purl.name,
        )
        if has_group_overlap and group_overlap_reason:
            for idx in indices:
                claim_results[idx] = _apply_triage_cap(
                    claim_results[idx],
                    tier_weight=tier_weight,
                    extra_reasons=(group_overlap_reason,),
                )

    accepted = tuple(cr for cr in claim_results if cr.routing != RoutingDecision.DROP)
    dropped = tuple(cr for cr in claim_results if cr.routing == RoutingDecision.DROP)

    pool = accepted if accepted else tuple(claim_results)
    top_claim = max(pool, key=lambda cr: cr.composite_score)
    advisory_specificity = top_claim.extraction_specificity
    advisory_composite = top_claim.composite_score
    advisory_routing = route_score(advisory_composite)

    advisory_reasons: list[str] = []
    if not accepted:
        advisory_reasons.append("All extracted package claims were dropped during verification.")
    elif dropped:
        advisory_reasons.append(
            f"Accepted {len(accepted)} claim(s); dropped {len(dropped)} unverified claim(s)."
        )

    return CredibilityReport(
        article_url=advisory.article_url,
        source_tier=article.source_tier,
        source_tier_weight=tier_weight,
        extraction_specificity=advisory_specificity,
        composite_score=advisory_composite,
        routing=advisory_routing,
        claim_results=tuple(claim_results),
        accepted_claims=accepted,
        dropped_claims=dropped,
        reasons=tuple(advisory_reasons),
    )
