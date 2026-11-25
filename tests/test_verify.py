"""Comprehensive offline unit tests for zerobom models and deterministic verify/ layer."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from zerobom.models import (
    ArticleType,
    ExtractedAdvisory,
    ExtractedPackageClaim,
    GroundingMatchType,
    GroundingStatus,
    OsvAdvisory,
    OsvAffected,
    OsvPackage,
    OsvRange,
    OsvRangeEvent,
    RawArticle,
    RegistryStatus,
    RoutingDecision,
    SourceTier,
    VersionConstraint,
    VulnerabilitySeverity,
)
from zerobom.verify import (
    HttpRegistryChecker,
    InMemoryRegistryCache,
    SqliteRegistryCache,
    check_distro_quote_grounding,
    check_quote_polarity,
    compile_osv_advisory,
    detect_overlapping_branch_ranges,
    evaluate_component_against_advisory,
    generate_precve_id,
    is_version_affected,
    is_version_in_osv_range,
    parse_ecosystem_version,
    parse_osv_ecosystem,
    parse_version_constraint,
    resolve_purl,
    route_score,
    strip_package_nvr_prefix,
    verify_advisory,
    verify_quote_grounding,
)

PUBLISHED_AT = datetime(2026, 3, 15, 14, 30, 0, tzinfo=UTC)


def _make_article(
    body: str,
    *,
    url: str = "https://security.example.org/advisories/pre-cve-demo",
    source_name: str = "Project Zero",
    source_tier: SourceTier = SourceTier.TIER_1,
) -> RawArticle:
    return RawArticle(
        url=url,
        title="Pre-CVE Advisory",
        body=body,
        source_name=source_name,
        source_tier=source_tier,
        published_at=PUBLISHED_AT,
    )


# ---------------------------------------------------------------------------
# 1. Strict Pydantic v2 Contracts
# ---------------------------------------------------------------------------


class TestStrictContracts:
    def test_extra_fields_and_coercion_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RawArticle(
                url="https://example.com/post",
                title="Title",
                body="Body text",
                source_name="Blog",
                source_tier="tier_1",  # type: ignore[arg-type]
                published_at=PUBLISHED_AT,
            )

        with pytest.raises(ValidationError):
            RawArticle(
                url="https://example.com/post",
                title="Title",
                body="Body text",
                source_name="Blog",
                published_at=PUBLISHED_AT,
                unexpected="boom",  # type: ignore[call-arg]
            )

        with pytest.raises(ValidationError):
            RawArticle(
                url="not-a-uri",
                title="Title",
                body="Body",
                source_name="Blog",
                published_at=PUBLISHED_AT,
            )

    def test_version_constraint_validators(self) -> None:
        with pytest.raises(ValidationError):
            VersionConstraint()

        with pytest.raises(ValidationError):
            VersionConstraint(fixed="   ")

        with pytest.raises(ValidationError):
            VersionConstraint(introduced="1.0.0", fixed="1.2.0", last_affected="1.1.9")

        with pytest.raises(ValidationError):
            VersionConstraint(exact="1.0.0", fixed="1.0.1")

        with pytest.raises(ValidationError):
            VersionConstraint(is_unbounded=True, fixed="1.0.1")

    def test_osv_contracts_and_rfc3339_utc_formatting(self) -> None:
        with pytest.raises(ValidationError):
            OsvRangeEvent()

        with pytest.raises(ValidationError):
            OsvRangeEvent(introduced="0", fixed="1.0.0")

        with pytest.raises(ValidationError):
            OsvRange(type="ECOSYSTEM", events=(OsvRangeEvent(fixed="1.0.0"),))

        plus_two = timezone(timedelta(hours=2))
        advisory = OsvAdvisory(
            id="PRECVE-2026-ABCDEF12",
            modified=datetime(2026, 3, 15, 16, 30, 0, tzinfo=plus_two),
            published=PUBLISHED_AT,
            summary="Sample summary",
            affected=(
                OsvAffected(
                    package=OsvPackage(
                        ecosystem="PyPI",
                        name="requests",
                        purl="pkg:pypi/requests",
                    ),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(
                                OsvRangeEvent(introduced="0"),
                                OsvRangeEvent(fixed="2.31.0"),
                            ),
                        ),
                    ),
                ),
            ),
        )
        as_dict = advisory.to_osv_dict()
        assert as_dict["schema_version"] == "1.6.7"
        assert as_dict["modified"] == "2026-03-15T14:30:00Z"
        assert as_dict["published"] == "2026-03-15T14:30:00Z"
        assert "aliases" not in as_dict
        assert "versions" not in as_dict["affected"][0]


# ---------------------------------------------------------------------------
# 2. Two-Stage Verbatim Quote Grounding
# ---------------------------------------------------------------------------


class TestQuoteGrounding:
    def test_exact_quote_verified(self) -> None:
        body = (
            "Our research uncovered an unauthenticated SSRF in Python requests "
            "versions prior to 2.31.0 when handling proxy redirects."
        )
        claim = ExtractedPackageClaim(
            raw_package_name="Python requests",
            ecosystem="pypi",
            version_constraints=(VersionConstraint(introduced="0", fixed="2.31.0"),),
            evidence_quote="unauthenticated SSRF in Python requests versions prior to 2.31.0",
        )
        res = verify_quote_grounding(body, claim, canonical_package_name="requests")
        assert res.status == GroundingStatus.VERIFIED
        assert res.match_type == GroundingMatchType.EXACT
        assert res.quote_found_in_article is True
        assert res.package_token_found is True
        assert res.version_tokens_found is True
        assert res.matched_span is not None
        start, end = res.matched_span
        assert body[start:end] == claim.evidence_quote

    def test_unicode_punctuation_and_whitespace_normalization(self) -> None:
        body = (
            "Advisory update:\u200b  “All versions of\n"
            "\tdjango\u2013rest\u2014framework before\u00a03.15.2” are affected."
        )
        claim = ExtractedPackageClaim(
            raw_package_name="django_rest_framework",
            ecosystem="pypi",
            version_constraints=(VersionConstraint(raw_specifier="prior to 3.15.2"),),
            evidence_quote='"All versions of django-rest-framework before 3.15.2" are affected.',
        )
        res = verify_quote_grounding(
            body,
            claim,
            canonical_package_name="django-rest-framework",
        )
        assert res.status == GroundingStatus.VERIFIED
        assert res.match_type == GroundingMatchType.NORMALIZED
        assert res.quote_found_in_article is True
        assert res.package_token_found is True
        assert res.version_tokens_found is True

    def test_bait_and_switch_missing_package_is_weak(self) -> None:
        body = (
            "Users running version 2.31.0 or earlier of the HTTP client should upgrade "
            "immediately to mitigate credential leakage."
        )
        claim = ExtractedPackageClaim(
            raw_package_name="requests",
            ecosystem="pypi",
            version_constraints=(VersionConstraint(introduced="0", last_affected="2.31.0"),),
            evidence_quote="Users running version 2.31.0 or earlier of the HTTP client",
        )
        res = verify_quote_grounding(body, claim, canonical_package_name="requests")
        assert res.status == GroundingStatus.QUOTE_ONLY_WEAK
        assert res.quote_found_in_article is True
        assert res.package_token_found is False
        assert res.version_tokens_found is True

    def test_bait_and_switch_missing_version_is_weak(self) -> None:
        body = (
            "Researchers reviewed the requests library architecture in depth this quarter "
            "and published general hardening advice."
        )
        claim = ExtractedPackageClaim(
            raw_package_name="requests",
            ecosystem="pypi",
            version_constraints=(VersionConstraint(introduced="0", fixed="2.31.0"),),
            evidence_quote="reviewed the requests library architecture in depth this quarter",
        )
        res = verify_quote_grounding(body, claim, canonical_package_name="requests")
        assert res.status == GroundingStatus.QUOTE_ONLY_WEAK
        assert res.quote_found_in_article is True
        assert res.package_token_found is True
        assert res.version_tokens_found is False

    def test_fabricated_and_short_quotes_are_ungrounded(self) -> None:
        body = "Today we patched an internal dashboard configuration issue."
        fabricated = ExtractedPackageClaim(
            raw_package_name="requests",
            ecosystem="pypi",
            version_constraints=(VersionConstraint(introduced="0", fixed="2.31.0"),),
            evidence_quote="requests prior to 2.31.0 allows remote code execution",
        )
        res_fab = verify_quote_grounding(body, fabricated, canonical_package_name="requests")
        assert res_fab.status == GroundingStatus.UNGROUNDED
        assert res_fab.match_type == GroundingMatchType.NONE
        assert res_fab.quote_found_in_article is False

        short = ExtractedPackageClaim(
            raw_package_name="requests",
            ecosystem="pypi",
            evidence_quote="requests 2.31",
        )
        res_short = verify_quote_grounding(
            "requests 2.31", short, canonical_package_name="requests"
        )
        assert res_short.status == GroundingStatus.UNGROUNDED

    def test_leading_v_tolerance_in_version_matching(self) -> None:
        body = "A bug in gin-gonic/gin v1.9.1 allows header smuggling."
        claim = ExtractedPackageClaim(
            raw_package_name="Go github.com/gin-gonic/gin",
            ecosystem="golang",
            version_constraints=(VersionConstraint(exact="1.9.1"),),
            evidence_quote="A bug in gin-gonic/gin v1.9.1 allows header smuggling.",
        )
        res = verify_quote_grounding(body, claim, canonical_package_name="gin")
        assert res.status == GroundingStatus.VERIFIED
        assert res.version_tokens_found is True

    @pytest.mark.parametrize("punct", [".", ",", ";", ":"])
    def test_trailing_punctuation_fallback_grounds_bullet_quote(self, punct: str) -> None:
        body = (
            "Fixed kernels are released to production:\n"
            "- kernel-4.18.0-553.177.1.lve.1.el8 for CloudLinux 8\n"
            "- kernel-5.14.0-687.60.1.el9_8 for CloudLinux 9"
        )
        claim = ExtractedPackageClaim(
            raw_package_name="kernel",
            ecosystem="rpm",
            namespace="cloudlinux",
            distro_release="8",
            version_constraints=(
                VersionConstraint(introduced="0", fixed="4.18.0-553.177.1.lve.1.el8"),
            ),
            evidence_quote=f"kernel-4.18.0-553.177.1.lve.1.el8 for CloudLinux 8{punct}",
        )
        res = verify_quote_grounding(body, claim, canonical_package_name="kernel")
        assert res.status == GroundingStatus.VERIFIED
        assert res.match_type == GroundingMatchType.NORMALIZED
        assert res.quote_found_in_article is True

    @pytest.mark.parametrize(
        ("article_version", "punct"),
        [
            ("8.2.35", ""),
            ("8.2.35", "."),
            ("8.2.35", ","),
            ("8.2.3.1", "."),
            ("8.2.3.1", ","),
            ("8.2.3-rc1", "."),
            ("8.2.3+deb11u1", "."),
        ],
    )
    def test_trailing_punctuation_fallback_rejects_partial_version_truncation_and_short_quotes(
        self,
        article_version: str,
        punct: str,
    ) -> None:
        body = f"PHP vulnerability is fixed in version {article_version}."
        truncated_claim = ExtractedPackageClaim(
            raw_package_name="php",
            ecosystem="generic",
            version_constraints=(VersionConstraint(introduced="0", fixed="8.2.3"),),
            evidence_quote=f"PHP vulnerability is fixed in version 8.2.3{punct}",
        )
        res = verify_quote_grounding(body, truncated_claim, canonical_package_name="php")
        assert res.status == GroundingStatus.UNGROUNDED
        assert res.quote_found_in_article is False

        padded_short_tokens = ExtractedPackageClaim(
            raw_package_name="requests",
            ecosystem="pypi",
            evidence_quote="requests 2.31...",
        )
        res_short_tokens = verify_quote_grounding(
            "requests 2.31...",
            padded_short_tokens,
            canonical_package_name="requests",
        )
        assert res_short_tokens.status == GroundingStatus.UNGROUNDED

        padded_short_after_strip = ExtractedPackageClaim(
            raw_package_name="requests",
            ecosystem="pypi",
            evidence_quote="requests v 2.3...",
        )
        res_short_after_strip = verify_quote_grounding(
            "requests v 2.3",
            padded_short_after_strip,
            canonical_package_name="requests",
        )
        assert res_short_after_strip.status == GroundingStatus.UNGROUNDED

    def test_bullet_and_colon_list_grounding_allows_same_list_and_blocks_stitch_attacks(
        self,
    ) -> None:
        crowdstrike_body = (
            "On October 21, 2026, PHP disclosed CVE-2026-109618 and CVE-2026-109619, "
            "which affect the following versions:\n"
            "- Earlier than 8.2.35\n"
            "- Earlier than 8.3.36\n"
            "- Earlier than 8.4.27\n"
            "- Earlier than 8.5.12"
        )
        contiguous_block = crowdstrike_body
        for fixed_ver in ("8.2.35", "8.3.36", "8.4.27", "8.5.12"):
            claim = ExtractedPackageClaim(
                raw_package_name="php",
                ecosystem="generic",
                version_constraints=(VersionConstraint(introduced="0", fixed=fixed_ver),),
                evidence_quote=contiguous_block,
            )
            res = verify_quote_grounding(crowdstrike_body, claim, canonical_package_name="php")
            assert res.status == GroundingStatus.VERIFIED

        # Same-list colon heading + non-adjacent bullet grounds each branch verbatim.
        for fixed_ver in ("8.3.36", "8.4.27", "8.5.12"):
            colon_claim = ExtractedPackageClaim(
                raw_package_name="php",
                ecosystem="generic",
                version_constraints=(VersionConstraint(introduced="0", fixed=fixed_ver),),
                evidence_quote=(
                    "On October 21, 2026, PHP disclosed CVE-2026-109618 and CVE-2026-109619, "
                    f"which affect the following versions: - Earlier than {fixed_ver}"
                ),
            )
            res = verify_quote_grounding(
                crowdstrike_body,
                colon_claim,
                canonical_package_name="php",
            )
            assert res.status == GroundingStatus.VERIFIED
            assert res.match_type == GroundingMatchType.NORMALIZED

        # Skipped intervening bullets MUST NOT leak their versions into Stage 2.
        cross_bullet_bait = ExtractedPackageClaim(
            raw_package_name="php",
            ecosystem="generic",
            version_constraints=(VersionConstraint(introduced="0", fixed="8.2.35"),),
            evidence_quote=(
                "On October 21, 2026, PHP disclosed CVE-2026-109618 and CVE-2026-109619, "
                "which affect the following versions: - Earlier than 8.5.12"
            ),
        )
        bait_res = verify_quote_grounding(
            crowdstrike_body, cross_bullet_bait, canonical_package_name="php"
        )
        assert bait_res.status == GroundingStatus.QUOTE_ONLY_WEAK
        assert bait_res.version_tokens_found is False

        # CloudLinux repeated heading across multiple update paragraphs (all 6 builds verify).
        cloudlinux_body = (
            "Update 1: Fixed kernels are released to production: "
            "kernel-4.18.0-553.177.1.lve.1.el7h for CloudLinux 7 hybrid, "
            "kernel-4.18.0-553.177.1.lve.1.el8 for CloudLinux 8.\n"
            "Update 2: Fixed kernels are released to production: "
            "kernel-5.14.0-687.60.1.el9_8 for CloudLinux 9, "
            "kernel-6.12.0-211.69.1.el10_2 for CloudLinux 10.\n"
            "Update 3: Fixed kernels are released to production: "
            "kernel-lts-5.14.0-284.1101.el8.tuxcare.11.els17 for CloudLinux 8 ELS, "
            "kernel-lts-5.14.0-284.1101.el9.tuxcare.11.els17 for CloudLinux 9 ELS."
        )
        cloudlinux_cases = [
            (
                "7",
                "4.18.0-553.177.1.lve.1.el7h",
                "kernel-4.18.0-553.177.1.lve.1.el7h for CloudLinux 7 hybrid",
            ),
            (
                "8",
                "4.18.0-553.177.1.lve.1.el8",
                "kernel-4.18.0-553.177.1.lve.1.el8 for CloudLinux 8.",
            ),
            ("9", "5.14.0-687.60.1.el9_8", "kernel-5.14.0-687.60.1.el9_8 for CloudLinux 9"),
            ("10", "6.12.0-211.69.1.el10_2", "kernel-6.12.0-211.69.1.el10_2 for CloudLinux 10."),
            (
                "8",
                "5.14.0-284.1101.el8.tuxcare.11.els17",
                "kernel-lts-5.14.0-284.1101.el8.tuxcare.11.els17 for CloudLinux 8 ELS",
            ),
            (
                "9",
                "5.14.0-284.1101.el9.tuxcare.11.els17",
                "kernel-lts-5.14.0-284.1101.el9.tuxcare.11.els17 for CloudLinux 9 ELS.",
            ),
        ]
        for rel, fixed_ver, item_text in cloudlinux_cases:
            cl_claim = ExtractedPackageClaim(
                raw_package_name="kernel",
                ecosystem="rpm",
                namespace="cloudlinux",
                distro_release=rel,
                version_constraints=(VersionConstraint(introduced="0", fixed=fixed_ver),),
                evidence_quote=f"Fixed kernels are released to production: {item_text}",
            )
            cl_res = verify_quote_grounding(
                cloudlinux_body,
                cl_claim,
                canonical_package_name="kernel",
            )
            assert cl_res.status == GroundingStatus.VERIFIED

        # Adversarial rejections that MUST fail closed as UNGROUNDED:
        prose_splice_body = (
            "Security review of requests library: no vulnerabilities were discovered. "
            "Meanwhile, our internal dashboard shipped version 2.31.0."
        )
        assert (
            verify_quote_grounding(
                prose_splice_body,
                ExtractedPackageClaim(
                    raw_package_name="requests",
                    ecosystem="pypi",
                    version_constraints=(VersionConstraint(introduced="0", fixed="2.31.0"),),
                    evidence_quote=(
                        "Security review of requests library: our internal dashboard "
                        "shipped version 2.31.0."
                    ),
                ),
                canonical_package_name="requests",
            ).status
            == GroundingStatus.UNGROUNDED
        )

        distant_body = (
            "Which PHP versions are affected by this flaw: "
            + ("filler item, " * 40)
            + "- Earlier than 8.3.36"
        )
        assert (
            verify_quote_grounding(
                distant_body,
                ExtractedPackageClaim(
                    raw_package_name="php",
                    ecosystem="generic",
                    version_constraints=(VersionConstraint(introduced="0", fixed="8.3.36"),),
                    evidence_quote=(
                        "Which PHP versions are affected by this flaw: - Earlier than 8.3.36"
                    ),
                ),
                canonical_package_name="php",
            ).status
            == GroundingStatus.UNGROUNDED
        )

        adversarial_crowdstrike_claims = [
            # Short colon prefix (< min_quote_length / min_quote_tokens)
            ("8.3.36", "PHP: - Earlier than 8.3.36"),
            # Bare single-token version suffix
            (
                "8.3.36",
                "On October 21, 2026, PHP disclosed CVE-2026-109618 and CVE-2026-109619, "
                "which affect the following versions: 8.3.36",
            ),
            # Truncated version token inside list item
            (
                "8.3.3",
                "On October 21, 2026, PHP disclosed CVE-2026-109618 and CVE-2026-109619, "
                "which affect the following versions: - Earlier than 8.3.3.",
            ),
            # Fabricated list item
            (
                "9.9.99",
                "On October 21, 2026, PHP disclosed CVE-2026-109618 and CVE-2026-109619, "
                "which affect the following versions: - Earlier than 9.9.99",
            ),
        ]
        for ver, quote in adversarial_crowdstrike_claims:
            adv_res = verify_quote_grounding(
                crowdstrike_body,
                ExtractedPackageClaim(
                    raw_package_name="php",
                    ecosystem="generic",
                    version_constraints=(VersionConstraint(introduced="0", fixed=ver),),
                    evidence_quote=quote,
                ),
                canonical_package_name="php",
            )
            assert adv_res.status == GroundingStatus.UNGROUNDED

        # Reversed order: item precedes heading in article.
        reversed_body = (
            "- Earlier than 8.3.36\n"
            "The section heading below does not introduce earlier bullets:\n"
            "PHP disclosed CVE-2026-109618 and CVE-2026-109619, "
            "which affect the following versions: none"
        )
        assert (
            verify_quote_grounding(
                reversed_body,
                ExtractedPackageClaim(
                    raw_package_name="php",
                    ecosystem="generic",
                    version_constraints=(VersionConstraint(introduced="0", fixed="8.3.36"),),
                    evidence_quote=(
                        "PHP disclosed CVE-2026-109618 and CVE-2026-109619, "
                        "which affect the following versions: - Earlier than 8.3.36"
                    ),
                ),
                canonical_package_name="php",
            ).status
            == GroundingStatus.UNGROUNDED
        )


# ---------------------------------------------------------------------------
# 3. Canonical PURL Resolution, Generic Blocklist & Cached Registry Checker
# ---------------------------------------------------------------------------


class TestPurlResolution:
    @pytest.mark.parametrize(
        ("raw_name", "ecosystem", "expected_purl", "expected_osv_eco"),
        [
            ("Python requests", None, "pkg:pypi/requests", "PyPI"),
            ("Django_Rest_Framework", "pypi", "pkg:pypi/django-rest-framework", "PyPI"),
            ("the package urllib3 (PyPI)", None, "pkg:pypi/urllib3", "PyPI"),
            ("npm @babel/traverse", None, "pkg:npm/%40babel/traverse", "npm"),
            ("Node.js lodash", None, "pkg:npm/lodash", "npm"),
            (
                "Maven org.apache.logging.log4j:log4j-core",
                None,
                "pkg:maven/org.apache.logging.log4j/log4j-core",
                "Maven",
            ),
            (
                "Go github.com/gin-gonic/gin",
                None,
                "pkg:golang/github.com/gin-gonic/gin",
                "Go",
            ),
            ("Debian openssl", None, "pkg:deb/debian/openssl", "Debian"),
            ("Ubuntu curl", None, "pkg:deb/ubuntu/curl", "Ubuntu"),
            ("rpm glibc", None, "pkg:rpm/redhat/glibc", "Red Hat"),
            ("Alpine musl", None, "pkg:apk/alpine/musl", "Alpine"),
            (
                "pkg:pypi/Django_Rest_Framework@3.14.0",
                None,
                "pkg:pypi/django-rest-framework",
                "PyPI",
            ),
        ],
    )
    def test_fuzzy_and_canonical_resolution(
        self,
        raw_name: str,
        ecosystem: str | None,
        expected_purl: str,
        expected_osv_eco: str,
    ) -> None:
        res = resolve_purl(raw_name, ecosystem=ecosystem)
        assert res.is_valid is True
        assert res.is_blocked_generic is False
        assert res.canonical_purl == expected_purl
        assert res.osv_ecosystem == expected_osv_eco
        assert res.registry_status == RegistryStatus.SKIPPED

    @pytest.mark.parametrize(
        ("raw_name", "ecosystem"),
        [
            ("core", "pypi"),
            ("utils", "npm"),
            ("app", "pypi"),
            ("server", "npm"),
            ("api", "maven"),
            ("x", "pypi"),
            ("Debian utils", None),
            ("Alpine core", None),
            ("pkg:deb/debian/utils", None),
        ],
    )
    def test_generic_blocklist_blocks_unnamespaced_and_distro_packages(
        self,
        raw_name: str,
        ecosystem: str | None,
    ) -> None:
        res = resolve_purl(raw_name, ecosystem=ecosystem)
        assert res.is_valid is False
        assert res.is_blocked_generic is True
        assert res.canonical_purl is None

    @pytest.mark.parametrize(
        ("raw_name", "ecosystem", "expected_purl"),
        [
            ("@myorg/utils", "npm", "pkg:npm/%40myorg/utils"),
            ("com.acme:core", "maven", "pkg:maven/com.acme/core"),
            ("github.com/myorg/app", "golang", "pkg:golang/github.com/myorg/app"),
        ],
    )
    def test_explicit_package_namespace_bypasses_generic_blocklist(
        self,
        raw_name: str,
        ecosystem: str,
        expected_purl: str,
    ) -> None:
        res = resolve_purl(raw_name, ecosystem=ecosystem)
        assert res.is_valid is True
        assert res.is_blocked_generic is False
        assert res.canonical_purl == expected_purl

    def test_http_registry_checker_outcomes_and_caches(self, tmp_path: Path) -> None:
        requests_seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            requests_seen.append(url)
            if "pypi.org/pypi/requests/json" in url:
                return httpx.Response(200, json={"info": {"name": "requests"}})
            if "pypi.org/pypi/hallucinated-pkg/json" in url:
                return httpx.Response(404)
            if "registry.npmjs.org/@babel%2Ftraverse" in url:
                return httpx.Response(200, json={"name": "@babel/traverse"})
            if "registry.npmjs.org/ghost-npm" in url:
                return httpx.Response(404)
            if "search.maven.org/solrsearch/select" in url:
                if "org.apache.logging.log4j" in url:
                    return httpx.Response(200, json={"response": {"numFound": 1}})
                return httpx.Response(200, json={"response": {"numFound": 0}})
            if "proxy.golang.org/github.com/!azure/go-autorest/@v/list" in url:
                return httpx.Response(200, text="v1.0.0\n")
            if "proxy.golang.org/github.com/acme/gone/@v/list" in url:
                return httpx.Response(410)
            if "pypi.org/pypi/flaky-pkg/json" in url:
                return httpx.Response(503)
            if "pypi.org/pypi/timeout-pkg/json" in url:
                raise httpx.ConnectTimeout("timed out", request=request)
            return httpx.Response(500)

        now = [1000.0]
        mem_cache = InMemoryRegistryCache(ttl_seconds=60.0, clock=lambda: now[0])
        client = httpx.Client(transport=httpx.MockTransport(handler))
        checker = HttpRegistryChecker(client=client, cache=mem_cache)

        # PyPI 200 -> EXISTS and cached
        res_ok = resolve_purl("requests", ecosystem="pypi", registry_checker=checker)
        assert res_ok.is_valid is True
        assert res_ok.registry_status == RegistryStatus.EXISTS
        assert len(requests_seen) == 1

        # Second call hits cache
        res_cached = resolve_purl("requests", ecosystem="pypi", registry_checker=checker)
        assert res_cached.registry_status == RegistryStatus.EXISTS
        assert len(requests_seen) == 1

        # After TTL expires, re-queries HTTP
        now[0] += 120.0
        resolve_purl("requests", ecosystem="pypi", registry_checker=checker)
        assert len(requests_seen) == 2

        # PyPI 404 -> NOT_FOUND -> invalid
        res_404 = resolve_purl("hallucinated-pkg", ecosystem="pypi", registry_checker=checker)
        assert res_404.is_valid is False
        assert res_404.registry_status == RegistryStatus.NOT_FOUND

        # Scoped npm 200 & unscoped 404
        assert (
            resolve_purl(
                "@babel/traverse", ecosystem="npm", registry_checker=checker
            ).registry_status
            == RegistryStatus.EXISTS
        )
        assert (
            resolve_purl("ghost-npm", ecosystem="npm", registry_checker=checker).is_valid is False
        )

        # Maven Central numFound > 0 vs 0 vs missing namespace
        assert (
            resolve_purl(
                "org.apache.logging.log4j:log4j-core",
                ecosystem="maven",
                registry_checker=checker,
            ).registry_status
            == RegistryStatus.EXISTS
        )
        assert (
            resolve_purl(
                "com.fake:missing-artifact",
                ecosystem="maven",
                registry_checker=checker,
            ).is_valid
            is False
        )
        assert (
            resolve_purl("log4j-core", ecosystem="maven", registry_checker=checker).registry_status
            == RegistryStatus.SKIPPED
        )

        # Go proxy uppercase !x escaping & 410 NOT_FOUND
        assert (
            resolve_purl(
                "github.com/Azure/go-autorest",
                ecosystem="golang",
                registry_checker=checker,
            ).registry_status
            == RegistryStatus.EXISTS
        )
        assert (
            resolve_purl(
                "github.com/acme/gone",
                ecosystem="golang",
                registry_checker=checker,
            ).is_valid
            is False
        )

        # Debian -> SKIPPED without HTTP request
        before_deb = len(requests_seen)
        res_deb = resolve_purl("Debian openssl", registry_checker=checker)
        assert res_deb.is_valid is True
        assert res_deb.registry_status == RegistryStatus.SKIPPED
        assert len(requests_seen) == before_deb

        # 503 & ConnectTimeout -> ERROR, keeps is_valid=True, not cached
        before_err = len(requests_seen)
        res_503 = resolve_purl("flaky-pkg", ecosystem="pypi", registry_checker=checker)
        assert res_503.is_valid is True
        assert res_503.registry_status == RegistryStatus.ERROR
        res_503_again = resolve_purl("flaky-pkg", ecosystem="pypi", registry_checker=checker)
        assert res_503_again.registry_status == RegistryStatus.ERROR
        assert len(requests_seen) == before_err + 2

        res_timeout = resolve_purl("timeout-pkg", ecosystem="pypi", registry_checker=checker)
        assert res_timeout.is_valid is True
        assert res_timeout.registry_status == RegistryStatus.ERROR

        # SQLite TTL cache persistence & expiration
        db_path = tmp_path / "cache" / "registry.sqlite"
        sql_clock = [5000.0]
        sql_cache = SqliteRegistryCache(db_path, ttl_seconds=30.0, clock=lambda: sql_clock[0])
        sql_checker = HttpRegistryChecker(client=client, cache=sql_cache)
        count_before = len(requests_seen)
        assert (
            resolve_purl("requests", ecosystem="pypi", registry_checker=sql_checker).registry_status
            == RegistryStatus.EXISTS
        )
        assert len(requests_seen) == count_before + 1

        # Re-open SQLite cache from disk -> cache hit
        sql_cache_reopened = SqliteRegistryCache(
            db_path,
            ttl_seconds=30.0,
            clock=lambda: sql_clock[0],
        )
        sql_checker_reopened = HttpRegistryChecker(client=client, cache=sql_cache_reopened)
        assert (
            resolve_purl(
                "requests",
                ecosystem="pypi",
                registry_checker=sql_checker_reopened,
            ).registry_status
            == RegistryStatus.EXISTS
        )
        assert len(requests_seen) == count_before + 1

        # Advance past TTL -> cache expired -> re-fetches
        sql_clock[0] += 45.0
        assert (
            resolve_purl(
                "requests",
                ecosystem="pypi",
                registry_checker=sql_checker_reopened,
            ).registry_status
            == RegistryStatus.EXISTS
        )
        assert len(requests_seen) == count_before + 2
        client.close()


# ---------------------------------------------------------------------------
# 4. Two-Axis Scoring & Credibility Gate Routing
# ---------------------------------------------------------------------------


class TestCredibilityScorer:
    def test_routing_threshold_boundaries(self) -> None:
        assert route_score(0.75) == RoutingDecision.AUTO
        assert route_score(0.7499) == RoutingDecision.TRIAGE
        assert route_score(0.50) == RoutingDecision.TRIAGE
        assert route_score(0.4999) == RoutingDecision.DROP

    def test_tier_routing_and_grounding_gates(self) -> None:
        body = (
            "Vulnerability confirmed in requests versions prior to 2.31.0 allowing SSRF. "
            "In unrelated news, internal server dashboards performed normally."
        )
        good_claim = ExtractedPackageClaim(
            raw_package_name="Python requests",
            ecosystem="pypi",
            version_constraints=(VersionConstraint(introduced="0", fixed="2.31.0"),),
            evidence_quote="requests versions prior to 2.31.0 allowing SSRF",
        )
        advisory_good = ExtractedAdvisory(
            article_url="https://security.example.org/advisories/requests",
            title="SSRF in requests",
            summary="SSRF in requests < 2.31.0",
            claims=(good_claim,),
            severity=VulnerabilitySeverity.HIGH,
        )

        # Tier 1 verified bounded -> AUTO
        report_t1 = verify_advisory(
            _make_article(body, source_tier=SourceTier.TIER_1),
            advisory_good,
        )
        assert report_t1.routing == RoutingDecision.AUTO
        assert report_t1.composite_score >= 0.75
        assert len(report_t1.accepted_claims) == 1

        # Tier 2 verified bounded -> AUTO (0.85 * 0.95 = 0.8075)
        report_t2 = verify_advisory(
            _make_article(body, source_tier=SourceTier.TIER_2),
            advisory_good,
        )
        assert report_t2.routing == RoutingDecision.AUTO
        assert report_t2.composite_score == pytest.approx(0.8075)

        # Unknown tier perfect claim -> capped at 0.55 (TRIAGE, never AUTO)
        report_unk = verify_advisory(
            _make_article(body, source_tier=SourceTier.UNKNOWN),
            ExtractedAdvisory(
                article_url=advisory_good.article_url,
                title=advisory_good.title,
                summary=advisory_good.summary,
                claims=(good_claim,),
                cwe_ids=("CWE-918",),
            ),
        )
        assert report_unk.routing == RoutingDecision.TRIAGE
        assert report_unk.composite_score <= 0.55

        # Ungrounded quote on Tier 1 -> DROP
        ungrounded_advisory = ExtractedAdvisory(
            article_url=advisory_good.article_url,
            title="Fake quote",
            summary="Hallucinated quote",
            claims=(
                ExtractedPackageClaim(
                    raw_package_name="requests",
                    ecosystem="pypi",
                    version_constraints=(VersionConstraint(introduced="0", fixed="2.31.0"),),
                    evidence_quote="requests 2.31.0 remote root exploit completely fabricated",
                ),
            ),
        )
        report_ungrounded = verify_advisory(
            _make_article(body, source_tier=SourceTier.TIER_1),
            ungrounded_advisory,
        )
        assert report_ungrounded.routing == RoutingDecision.DROP
        assert report_ungrounded.composite_score < 0.50
        assert len(report_ungrounded.accepted_claims) == 0

        # Weak quote (missing version inside quote) on Tier 1 -> TRIAGE (never AUTO)
        weak_body = "We observed unexpected behavior in the requests HTTP library during testing."
        weak_advisory = ExtractedAdvisory(
            article_url=advisory_good.article_url,
            title="Weak quote",
            summary="Missing version in quote",
            claims=(
                ExtractedPackageClaim(
                    raw_package_name="requests",
                    ecosystem="pypi",
                    version_constraints=(VersionConstraint(introduced="0", fixed="2.31.0"),),
                    evidence_quote="unexpected behavior in the requests HTTP library",
                ),
            ),
        )
        report_weak = verify_advisory(
            _make_article(weak_body, source_tier=SourceTier.TIER_1),
            weak_advisory,
        )
        assert report_weak.routing == RoutingDecision.TRIAGE
        assert 0.50 <= report_weak.composite_score < 0.75

    def test_blocked_generic_404_marketing_and_multi_claim_filtering(self) -> None:
        body = (
            "We patched a critical vulnerability in requests prior to 2.31.0. "
            "Meanwhile the core server utils component was also mentioned."
        )
        good_claim = ExtractedPackageClaim(
            raw_package_name="requests",
            ecosystem="pypi",
            version_constraints=(VersionConstraint(introduced="0", fixed="2.31.0"),),
            evidence_quote="vulnerability in requests prior to 2.31.0",
        )
        generic_claim = ExtractedPackageClaim(
            raw_package_name="utils",
            ecosystem="pypi",
            version_constraints=(VersionConstraint(introduced="0", fixed="1.0.0"),),
            evidence_quote="the core server utils component was also mentioned",
        )
        mixed_advisory = ExtractedAdvisory(
            article_url="https://security.example.org/mixed",
            title="Mixed advisory",
            summary="Good + generic",
            claims=(good_claim, generic_claim),
        )
        report = verify_advisory(_make_article(body), mixed_advisory)
        assert report.routing == RoutingDecision.AUTO
        assert len(report.accepted_claims) == 1
        assert report.accepted_claims[0].purl.canonical_purl == "pkg:pypi/requests"
        assert len(report.dropped_claims) == 1
        assert report.dropped_claims[0].composite_score == 0.0
        assert report.dropped_claims[0].purl.is_blocked_generic is True

        # Registry 404 hard-drops valid-looking PURL
        def not_found_handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        client = httpx.Client(transport=httpx.MockTransport(not_found_handler))
        checker = HttpRegistryChecker(client=client)
        report_404 = verify_advisory(
            _make_article(body),
            ExtractedAdvisory(
                article_url="https://security.example.org/404",
                title="404 package",
                summary="Does not exist",
                claims=(good_claim,),
            ),
            registry_checker=checker,
        )
        client.close()
        assert report_404.routing == RoutingDecision.DROP
        assert report_404.composite_score == 0.0

        # Zero-claim marketing post -> DROP
        report_marketing = verify_advisory(
            _make_article("Join us at RSA Conference for exciting product announcements!"),
            ExtractedAdvisory(
                article_url="https://security.example.org/marketing",
                title="RSA Promo",
                summary="Marketing announcement",
                claims=(),
            ),
        )
        assert report_marketing.routing == RoutingDecision.DROP
        assert report_marketing.composite_score == 0.0


# ---------------------------------------------------------------------------
# 5. OSV Compilation, Deterministic IDs & Multi-Ecosystem Version Math
# ---------------------------------------------------------------------------


class TestOsvCompilerAndVersionMath:
    def test_deterministic_precve_id_and_url_canonicalization(self) -> None:
        id1 = generate_precve_id(
            "https://Blog.Example.com/posts/2026/advisory/?utm_source=rss&b=2&a=1#top",
            ("pkg:npm/lodash", "pkg:pypi/requests"),
            published_at=PUBLISHED_AT,
        )
        id2 = generate_precve_id(
            "https://blog.example.com/posts/2026/advisory?a=1&b=2&fbclid=xyz",
            ("pkg:pypi/requests", "pkg:npm/lodash"),
            published_at=PUBLISHED_AT,
        )
        assert id1 == id2
        assert id1.startswith("PRECVE-2026-")
        assert len(id1) == len("PRECVE-2026-ABCDEF12")

        id_diff_url = generate_precve_id(
            "https://blog.example.com/posts/2026/other",
            ("pkg:pypi/requests", "pkg:npm/lodash"),
            published_at=PUBLISHED_AT,
        )
        assert id_diff_url != id1

    def test_compile_osv_advisory_merges_ranges_and_drops_rejected_claims(self) -> None:
        body = (
            "A flaw in npm lodash versions 1.0.0 through 1.4.1 and 2.0.0 prior to 2.1.5 "
            "plus exact release 3.0.0-alpha permits prototype pollution. "
            "Meanwhile generic core package is unaffected."
        )
        claim_range_1 = ExtractedPackageClaim(
            raw_package_name="lodash",
            ecosystem="npm",
            version_constraints=(
                VersionConstraint(introduced="1.0.0", fixed="1.4.2"),
                VersionConstraint(raw_specifier=">= 2.0.0, < 2.1.5"),
                VersionConstraint(exact="3.0.0-alpha"),
            ),
            evidence_quote="npm lodash versions 1.0.0 through 1.4.1 and 2.0.0 prior to 2.1.5",
            fix_commit_url="https://github.com/lodash/lodash/commit/deadbeef",
            poc_url="https://example.org/poc",
        )
        claim_dropped = ExtractedPackageClaim(
            raw_package_name="core",
            ecosystem="npm",
            version_constraints=(VersionConstraint(introduced="0", fixed="1.0.0"),),
            evidence_quote="generic core package is unaffected",
        )
        advisory = ExtractedAdvisory(
            article_url="https://security.example.org/lodash-bug",
            title="Prototype pollution in lodash",
            summary="Prototype pollution in lodash",
            details="Detailed technical writeup.",
            claims=(claim_range_1, claim_dropped),
            severity=VulnerabilitySeverity.HIGH,
            cwe_ids=("CWE-1321",),
            references=("https://github.com/lodash/lodash/issues/9999",),
            published_at=PUBLISHED_AT,
        )
        article = _make_article(body, url=advisory.article_url)
        report = verify_advisory(article, advisory)
        compiled = compile_osv_advisory(
            advisory,
            report,
            article=article,
            advisory_id="PRECVE-2026-0001",
        )
        assert compiled is not None
        assert compiled.id == "PRECVE-2026-0001"
        assert len(compiled.affected) == 1
        affected = compiled.affected[0]
        assert affected.package.ecosystem == "npm"
        assert affected.package.purl == "pkg:npm/lodash"
        assert affected.versions == ("3.0.0-alpha",)
        assert len(affected.ranges) == 1
        assert affected.ranges[0].type == "SEMVER"
        assert len(affected.ranges[0].events) == 4

        osv_dict = compiled.to_osv_dict()
        ref_types = {r["type"] for r in osv_dict["references"]}
        assert ref_types == {"ARTICLE", "FIX", "EVIDENCE", "WEB"}
        assert osv_dict["database_specific"]["zerobom"]["source_name"] == "Project Zero"

        # If no claims accepted -> returns None
        rejected_report = verify_advisory(
            _make_article("Unrelated text"),
            ExtractedAdvisory(
                article_url="https://security.example.org/none",
                title="Empty",
                summary="Empty",
                claims=(claim_dropped,),
            ),
        )
        assert compile_osv_advisory(advisory, rejected_report) is None

    def test_inverted_bounds_strict_gt_and_natural_language_constraints(self) -> None:
        inverted = parse_version_constraint(
            "pypi",
            VersionConstraint(introduced="2.0.0", fixed="1.0.0"),
        )
        assert inverted.is_valid is False

        strict_gt = parse_version_constraint("npm", VersionConstraint(raw_specifier="> 1.0.0"))
        assert strict_gt.is_valid is False

        invalid_ver = parse_version_constraint("pypi", VersionConstraint(fixed="not_a_ver!@#"))
        assert invalid_ver.is_valid is False

        hyphen = parse_version_constraint("npm", VersionConstraint(raw_specifier="1.2.0 - 1.5.3"))
        assert hyphen.is_valid is True
        assert hyphen.is_bounded is True
        assert hyphen.events[0].introduced == "1.2.0"
        assert hyphen.events[1].last_affected == "1.5.3"

        nl_leq = parse_version_constraint(
            "pypi",
            VersionConstraint(raw_specifier="2.14.1 and earlier"),
        )
        assert nl_leq.is_valid is True
        assert nl_leq.events[1].last_affected == "2.14.1"

        nl_all = parse_version_constraint("pypi", VersionConstraint(raw_specifier="all versions"))
        assert nl_all.is_valid is True
        assert nl_all.is_bounded is False

    def test_pypi_pep440_version_math(self) -> None:
        assert parse_ecosystem_version("pypi", "2.31.0a1") < parse_ecosystem_version(
            "pypi", "2.31.0"
        )
        assert parse_ecosystem_version("pypi", "2.31.0.post1") > parse_ecosystem_version(
            "pypi", "2.31.0"
        )
        assert parse_ecosystem_version("pypi", "1!1.0.0") > parse_ecosystem_version(
            "pypi", "2.31.0"
        )
        assert parse_ecosystem_version("pypi", "1.2.0.dev0") < parse_ecosystem_version(
            "pypi", "1.2.0"
        )

        osv_range = OsvRange(
            type="ECOSYSTEM",
            events=(OsvRangeEvent(introduced="0"), OsvRangeEvent(fixed="2.31.0")),
        )
        assert is_version_in_osv_range("pypi", "2.30.9", osv_range) is True
        assert is_version_in_osv_range("pypi", "2.31.0a1", osv_range) is True
        assert is_version_in_osv_range("pypi", "1.2.0.dev0", osv_range) is True
        assert is_version_in_osv_range("pypi", "2.31.0", osv_range) is False
        assert is_version_in_osv_range("pypi", "2.31.0.post1", osv_range) is False
        assert is_version_in_osv_range("pypi", "1!1.0.0", osv_range) is False

    def test_npm_semver_multi_branch_and_last_affected(self) -> None:
        assert parse_ecosystem_version("npm", "1.5.4-rc.1") < parse_ecosystem_version(
            "npm", "1.5.4"
        )

        multi_branch = OsvRange(
            type="SEMVER",
            events=(
                OsvRangeEvent(introduced="1.0.0"),
                OsvRangeEvent(fixed="1.4.2"),
                OsvRangeEvent(introduced="2.0.0"),
                OsvRangeEvent(fixed="2.1.5"),
            ),
        )
        assert is_version_in_osv_range("npm", "1.0.0", multi_branch) is True
        assert is_version_in_osv_range("npm", "1.4.1", multi_branch) is True
        assert is_version_in_osv_range("npm", "1.4.2", multi_branch) is False
        assert is_version_in_osv_range("npm", "1.9.0", multi_branch) is False
        assert is_version_in_osv_range("npm", "2.1.5-rc.1", multi_branch) is True
        assert is_version_in_osv_range("npm", "2.1.5", multi_branch) is False

        inclusive_range = OsvRange(
            type="SEMVER",
            events=(
                OsvRangeEvent(introduced="1.0.0"),
                OsvRangeEvent(last_affected="1.4.2"),
            ),
        )
        assert is_version_in_osv_range("npm", "1.4.2", inclusive_range) is True
        assert is_version_in_osv_range("npm", "1.4.3", inclusive_range) is False

    def test_maven_qualifier_version_math(self) -> None:
        a1 = parse_ecosystem_version("maven", "1.0-alpha-1")
        b1 = parse_ecosystem_version("maven", "1.0-beta-1")
        rc1 = parse_ecosystem_version("maven", "1.0-RC1")
        rel = parse_ecosystem_version("maven", "1.0")
        assert a1 < b1 < rc1 < rel

        log4j_range = OsvRange(
            type="ECOSYSTEM",
            events=(OsvRangeEvent(introduced="2.0-beta9"), OsvRangeEvent(fixed="2.15.0")),
        )
        assert is_version_in_osv_range("maven", "2.0-beta9", log4j_range) is True
        assert is_version_in_osv_range("maven", "2.14.1", log4j_range) is True
        assert is_version_in_osv_range("maven", "2.15.0-rc1", log4j_range) is True
        assert is_version_in_osv_range("maven", "2.0-beta8", log4j_range) is False
        assert is_version_in_osv_range("maven", "2.15.0", log4j_range) is False

    def test_debian_dpkg_tilde_backports_and_epochs(self) -> None:
        assert parse_ecosystem_version("deb", "1.1.1~rc1") < parse_ecosystem_version(
            "deb", "1.1.1-1"
        )
        assert parse_ecosystem_version("deb", "1.1.1n-0+deb11u4") < parse_ecosystem_version(
            "deb", "1.1.1n-0+deb11u5"
        )
        assert parse_ecosystem_version("deb", "1:1.0.0-1") > parse_ecosystem_version(
            "deb", "2.0.0-1"
        )

        deb_range = OsvRange(
            type="ECOSYSTEM",
            events=(
                OsvRangeEvent(introduced="0"),
                OsvRangeEvent(fixed="1.1.1n-0+deb11u5"),
            ),
        )
        assert is_version_in_osv_range("Debian", "0~alpha1", deb_range) is True
        assert is_version_in_osv_range("Debian", "1.1.1~rc1", deb_range) is True
        assert is_version_in_osv_range("Debian", "1.1.1n-0+deb11u4", deb_range) is True
        assert is_version_in_osv_range("Debian", "1.1.1n-0+deb11u5", deb_range) is False
        assert is_version_in_osv_range("Debian", "1:1.0.0-1", deb_range) is False

    def test_go_version_math_and_evaluate_component_against_advisory(self) -> None:
        assert parse_ecosystem_version("golang", "v1.10.0") > parse_ecosystem_version(
            "golang", "v1.2.0"
        )
        go_affected = OsvAffected(
            package=OsvPackage(
                ecosystem="Go",
                name="github.com/gin-gonic/gin",
                purl="pkg:golang/github.com/gin-gonic/gin",
            ),
            ranges=(
                OsvRange(
                    type="SEMVER",
                    events=(OsvRangeEvent(introduced="v1.0.0"), OsvRangeEvent(fixed="v1.10.0")),
                ),
            ),
        )
        assert is_version_affected("Go", "v1.2.0", go_affected) is True
        assert is_version_affected("Go", "v1.10.0", go_affected) is False

        # End-to-end compile + evaluate_component_against_advisory
        body = "We discovered an SSRF bug in Python requests prior to 2.31.0."
        advisory = ExtractedAdvisory(
            article_url="https://security.example.org/requests-ssrf",
            title="SSRF in requests",
            summary="SSRF in requests < 2.31.0",
            claims=(
                ExtractedPackageClaim(
                    raw_package_name="Python requests",
                    ecosystem="pypi",
                    version_constraints=(VersionConstraint(introduced="0", fixed="2.31.0"),),
                    evidence_quote="SSRF bug in Python requests prior to 2.31.0",
                ),
            ),
            published_at=PUBLISHED_AT,
        )
        article = _make_article(body, url=advisory.article_url)
        report = verify_advisory(article, advisory)
        osv = compile_osv_advisory(advisory, report, article=article)
        assert osv is not None

        hit: Any = evaluate_component_against_advisory(
            osv,
            "pkg:pypi/Requests@2.30.0",
            sbom_source="sbom.cdx.json",
        )
        assert hit is not None
        assert hit.is_vulnerable is True
        assert hit.matched_purl == "pkg:pypi/requests"
        assert hit.fixed_versions == ("2.31.0",)
        assert hit.sbom_source == "sbom.cdx.json"

        patched = evaluate_component_against_advisory(osv, "pkg:pypi/requests@2.31.0")
        assert patched is not None
        assert patched.is_vulnerable is False

        unrelated = evaluate_component_against_advisory(osv, "pkg:pypi/httpx@0.27.0")
        assert unrelated is None


# ---------------------------------------------------------------------------
# 6. Security Hardening & Injection-Proofing Regression Tests
# ---------------------------------------------------------------------------


class TestSecurityHardening:
    @pytest.mark.parametrize(
        "bad_uri",
        [
            "javascript://alert(1)",
            "data://text/html,<script>alert(1)</script>",
            "gopher://127.0.0.1:6379/_INFO",
            "https://example.com/a\r\nb",
            "https://example.com/path\x00null",
            "https://",
            f"https://example.com/{'a' * 2050}",
        ],
    )
    def test_uri_scheme_allowlist_length_and_crlf_rejection(self, bad_uri: str) -> None:
        with pytest.raises(ValidationError):
            RawArticle(
                url=bad_uri,
                title="Test",
                body="Body",
                source_name="Blog",
                published_at=PUBLISHED_AT,
            )

        with pytest.raises(ValidationError):
            ExtractedPackageClaim(
                raw_package_name="requests",
                ecosystem="pypi",
                evidence_quote="requests prior to 2.31.0 is vulnerable",
                fix_commit_url=bad_uri,
            )

        with pytest.raises(ValidationError):
            ExtractedPackageClaim(
                raw_package_name="requests",
                ecosystem="pypi",
                evidence_quote="requests prior to 2.31.0 is vulnerable",
                poc_url=bad_uri,
            )

        with pytest.raises(ValidationError):
            ExtractedAdvisory(
                article_url="https://example.org/advisory",
                title="Test",
                summary="Summary",
                references=(bad_uri,),
            )

    def test_maven_solr_injection_and_traversal_blocked_before_http(self) -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            return httpx.Response(200, json={"response": {"numFound": 1}})

        client = httpx.Client(transport=httpx.MockTransport(handler))
        checker = HttpRegistryChecker(client=client)

        # Malicious coordinates via resolve_purl fail resolution immediately without HTTP.
        for bad_raw in (
            "Maven org.apache OR *:*",
            'Maven com.acme:foo" OR g:*',
            "Go github.com/../../etc/passwd",
            "Go github.com/org/repo?x=1#y",
            "npm ../evil",
            "pypi req\\uests",
        ):
            res = resolve_purl(bad_raw, registry_checker=checker)
            assert res.is_valid is False
            assert res.canonical_purl is None

        # Even if a crafted PURL is fed directly to HttpRegistryChecker, it skips HTTP.
        for crafted_purl in (
            'pkg:maven/foo" OR g:*/bar',
            "pkg:maven/org.apache OR */log4j-core",
            "pkg:golang/github.com/../../etc/passwd",
            "pkg:golang/github.com/org/repo?x=1#y",
            "pkg:golang/github.com/org/repo%3Fx=1",
            "pkg:npm/../evil",
            "pkg:pypi/requests\r\nHost:evil.test",
        ):
            assert checker.check(crafted_purl) == RegistryStatus.SKIPPED

        assert calls == []
        client.close()

    def test_oversized_and_control_char_versions_rejected_cleanly(self) -> None:
        long_ver = "1." + ("0." * 70) + "1"
        assert len(long_ver) > 128
        with pytest.raises(ValueError, match="maximum length"):
            parse_ecosystem_version("pypi", long_ver)

        with pytest.raises(ValueError, match="control characters"):
            parse_ecosystem_version("npm", "1.2.3\r\n")

        oversized_spec = ">= 1.0.0, " + ("< 9.9.9, " * 35) + "< 9.9.9"
        parsed_long = parse_version_constraint(
            "npm",
            VersionConstraint(raw_specifier=oversized_spec),
        )
        assert parsed_long.is_valid is False

        parsed_ctrl = parse_version_constraint(
            "npm",
            VersionConstraint(raw_specifier=">= 1.0.0\x00"),
        )
        assert parsed_ctrl.is_valid is False

    def test_corrupted_sqlite_cache_row_evicted_safely(self, tmp_path: Path) -> None:
        db_path = tmp_path / "corrupt.sqlite"
        cache = SqliteRegistryCache(db_path, ttl_seconds=60.0)
        purl = "pkg:pypi/requests"

        conn = sqlite3.connect(db_path)
        try:
            with conn:
                conn.execute(
                    "INSERT INTO registry_cache (purl, status, checked_at) VALUES (?, ?, ?)",
                    (purl, "UNEXPECTED_TAMPERED_STATE", 9999999999.0),
                )
        finally:
            conn.close()

        assert cache.get(purl) is None

        # Verify tampered row was evicted cleanly.
        conn_check = sqlite3.connect(db_path)
        try:
            remaining = conn_check.execute(
                "SELECT status FROM registry_cache WHERE purl = ?",
                (purl,),
            ).fetchone()
            assert remaining is None
        finally:
            conn_check.close()

    def test_default_http_registry_checker_disables_redirects(self) -> None:
        with HttpRegistryChecker() as checker:
            assert checker.client.follow_redirects is False


# ---------------------------------------------------------------------------
# 6. Ecosystem-Aware Generic Blocklist, NVR, Distro Streams & Multi-Quote
# ---------------------------------------------------------------------------


class TestHardeningAndRealWorldFormats:
    def test_ecosystem_aware_blocklist_and_arbitrary_distro_namespaces(self) -> None:
        cl_kernel = resolve_purl("kernel", ecosystem="rpm", namespace="cloudlinux")
        assert cl_kernel.is_valid is True
        assert cl_kernel.is_blocked_generic is False
        assert cl_kernel.canonical_purl == "pkg:rpm/cloudlinux/kernel"
        assert cl_kernel.osv_ecosystem == "CloudLinux"

        euro_kernel = resolve_purl("kernel", ecosystem="rpm", namespace="eurolinux")
        assert euro_kernel.is_valid is True
        assert euro_kernel.canonical_purl == "pkg:rpm/eurolinux/kernel"
        assert euro_kernel.osv_ecosystem == "eurolinux"

        generic_ruby = resolve_purl("ruby", ecosystem="generic")
        assert generic_ruby.is_valid is True
        assert generic_ruby.is_blocked_generic is False
        assert generic_ruby.canonical_purl == "pkg:generic/ruby"
        assert generic_ruby.osv_ecosystem == "Generic"

        # Runtime/OS words remain blocked on library registries without explicit namespaces,
        # and generic noise words ('utils', 'core') remain blocked even on distros.
        for bad_raw, bad_eco, bad_ns in (
            ("ruby", "gem", None),
            ("kernel", "pypi", None),
            ("python", "pypi", None),
            ("node", "npm", None),
            ("utils", "deb", "debian"),
            ("core", "rpm", "cloudlinux"),
        ):
            blocked = resolve_purl(bad_raw, ecosystem=bad_eco, namespace=bad_ns)
            assert blocked.is_valid is False
            assert blocked.is_blocked_generic is True

        # Reject malformed characters inside explicit distro namespaces.
        bad_ns_res = resolve_purl("kernel", ecosystem="rpm", namespace="bad/ns")
        assert bad_ns_res.is_valid is False

    def test_nvr_prefix_stripping_and_custom_distro_osv_evaluation(self) -> None:
        assert strip_package_nvr_prefix("kernel-5.14.0-687.60.1.el9_8", "kernel") == (
            "5.14.0-687.60.1.el9_8"
        )
        assert (
            strip_package_nvr_prefix(
                "kernel-lts-5.14.0-284.1101.el8.tuxcare.11.els17", "kernel-lts"
            )
            == "5.14.0-284.1101.el8.tuxcare.11.els17"
        )
        # Non-digit suffixes are never stripped into broken versions.
        assert strip_package_nvr_prefix("kernel-lts-5.14.0", "kernel") == "kernel-lts-5.14.0"

        parsed = parse_version_constraint(
            "rpm",
            VersionConstraint(introduced="0", fixed="kernel-5.14.0-687.60.1.el9_8"),
            package_name="kernel",
        )
        assert parsed.is_valid is True
        assert parsed.is_bounded is True
        assert parsed.events[1].fixed == "5.14.0-687.60.1.el9_8"

        # Verify custom unmapped distro ("eurolinux:9") evaluates via PURL type fallback ("rpm").
        article = RawArticle(
            url="https://sec.example.org/eurolinux-kernel-nvr",
            title="EuroLinux 9 kernel NVR advisory",
            body=(
                "EuroLinux 9 patched package kernel prior to kernel-5.14.0-687.60.1.el9_8 "
                "for remote privilege escalation."
            ),
            source_name="EuroSec",
            source_tier=SourceTier.TIER_1,
            published_at=datetime(2026, 10, 30, tzinfo=UTC),
        )
        advisory = ExtractedAdvisory(
            article_url=article.url,
            title=article.title,
            summary="EuroLinux 9 kernel patch.",
            claims=(
                ExtractedPackageClaim(
                    raw_package_name="kernel",
                    ecosystem="rpm",
                    namespace="eurolinux",
                    distro_release="9",
                    version_constraints=(
                        VersionConstraint(introduced="0", fixed="kernel-5.14.0-687.60.1.el9_8"),
                    ),
                    evidence_quote=(
                        "EuroLinux 9 patched package kernel prior to kernel-5.14.0-687.60.1.el9_8 "
                        "for remote privilege escalation."
                    ),
                ),
            ),
        )
        report = verify_advisory(article, advisory)
        assert report.routing == RoutingDecision.AUTO
        osv = compile_osv_advisory(advisory, report, article=article)
        assert osv is not None
        assert osv.affected[0].package.ecosystem == "eurolinux:9"
        hit = evaluate_component_against_advisory(
            osv,
            "pkg:rpm/eurolinux/kernel@5.14.0-687.59.1.el9_8?distro=eurolinux-9",
        )
        clean = evaluate_component_against_advisory(
            osv,
            "pkg:rpm/eurolinux/kernel@5.14.0-687.60.1.el9_8?distro=eurolinux-9",
        )
        assert hit is not None and hit.is_vulnerable is True
        assert clean is not None and clean.is_vulnerable is False

    def test_distro_stream_isolation_prevents_cl8_cl9_false_positives(self) -> None:
        article = RawArticle(
            url="https://blog.cloudlinux.example/zdi-can-33367",
            title="CloudLinux Kernel Security Update (ZDI-CAN-33367)",
            body=(
                "CloudLinux 8 builds are fixed in kernel-4.18.0-553.el8.\n"
                "CloudLinux 9 builds are fixed in kernel-5.14.0-687.60.1.el9_8."
            ),
            source_name="CloudLinux Blog",
            source_tier=SourceTier.TIER_1,
            published_at=datetime(2026, 10, 30, tzinfo=UTC),
        )
        advisory = ExtractedAdvisory(
            article_url=article.url,
            title=article.title,
            summary="Multi-stream CloudLinux kernel fixes.",
            claims=(
                ExtractedPackageClaim(
                    raw_package_name="kernel",
                    ecosystem="rpm",
                    namespace="cloudlinux",
                    distro_release="8",
                    version_constraints=(
                        VersionConstraint(introduced="0", fixed="kernel-4.18.0-553.el8"),
                    ),
                    evidence_quote="CloudLinux 8 builds are fixed in kernel-4.18.0-553.el8.",
                ),
                ExtractedPackageClaim(
                    raw_package_name="kernel",
                    ecosystem="rpm",
                    namespace="cloudlinux",
                    distro_release="9",
                    version_constraints=(
                        VersionConstraint(introduced="0", fixed="kernel-5.14.0-687.60.1.el9_8"),
                    ),
                    evidence_quote="CloudLinux 9 builds are fixed in kernel-5.14.0-687.60.1.el9_8.",
                ),
            ),
            known_aliases=("ZDI-CAN-33367",),
        )
        report = verify_advisory(article, advisory)
        osv = compile_osv_advisory(advisory, report, article=article)
        assert osv is not None
        assert len(osv.affected) == 2

        cl8_patched = evaluate_component_against_advisory(
            osv, "pkg:rpm/cloudlinux/kernel@4.18.0-553.el8?distro=cloudlinux-8"
        )
        cl8_vuln = evaluate_component_against_advisory(
            osv, "pkg:rpm/cloudlinux/kernel@4.18.0-552.el8?distro=cloudlinux-8"
        )
        cl9_vuln = evaluate_component_against_advisory(
            osv, "pkg:rpm/cloudlinux/kernel@5.14.0-687.59.1.el9_8?distro=cloudlinux-9"
        )
        assert cl8_patched is not None and cl8_patched.is_vulnerable is False
        assert cl8_vuln is not None and cl8_vuln.is_vulnerable is True
        assert cl9_vuln is not None and cl9_vuln.is_vulnerable is True

    def test_generic_multibranch_ruby_version_math(self) -> None:
        article = RawArticle(
            url="https://rubysec.example/ruby2shell",
            title="Ruby2Shell Arbitrary Code Execution in MRI Ruby",
            body=(
                "A critical defect affects upstream ruby branches from 3.2.0 before 3.2.7, "
                "3.3.0 before 3.3.7, and 3.4.0 before 3.4.2."
            ),
            source_name="RubySec",
            source_tier=SourceTier.TIER_1,
            published_at=datetime(2026, 11, 1, tzinfo=UTC),
        )
        advisory = ExtractedAdvisory(
            article_url=article.url,
            title=article.title,
            summary="Multi-branch RCE in ruby runtime.",
            claims=(
                ExtractedPackageClaim(
                    raw_package_name="ruby",
                    ecosystem="generic",
                    version_constraints=(
                        VersionConstraint(introduced="3.2.0", fixed="3.2.7"),
                        VersionConstraint(introduced="3.3.0", fixed="3.3.7"),
                        VersionConstraint(introduced="3.4.0", fixed="3.4.2"),
                    ),
                    evidence_quote=(
                        "A critical defect affects upstream ruby branches from 3.2.0 before 3.2.7, "
                        "3.3.0 before 3.3.7, and 3.4.0 before 3.4.2."
                    ),
                ),
            ),
        )
        report = verify_advisory(article, advisory)
        assert report.routing == RoutingDecision.AUTO
        osv = compile_osv_advisory(advisory, report, article=article)
        assert osv is not None

        for ver, exp_vuln in (
            ("3.2.6", True),
            ("3.2.7", False),
            ("3.3.6", True),
            ("3.3.7", False),
            ("3.4.1", True),
            ("3.4.2", False),
        ):
            mr = evaluate_component_against_advisory(osv, "pkg:generic/ruby", ver)
            assert mr is not None and mr.is_vulnerable is exp_vuln

    def test_multi_quote_grounding_valid_fabricated_and_split_stitch(self) -> None:
        body = (
            "Paragraph 1: CloudLinux kernel received an urgent security patch in "
            "5.14.0-687.60.1.el9_8.\n"
            "Paragraph 2: Update notes also confirm kernel-5.14.0-687.60.1.el9_8 fixes the flaw, "
            "whereas earlier branch 4.18.0-553.el8 remediated CL8.\n"
            "Paragraph 3: Unrelated note mentions requests library HTTP timeouts."
        )
        valid_multi = ExtractedPackageClaim(
            raw_package_name="kernel",
            ecosystem="rpm",
            namespace="cloudlinux",
            version_constraints=(
                VersionConstraint(introduced="0", fixed="kernel-5.14.0-687.60.1.el9_8"),
            ),
            evidence_quote=(
                "Paragraph 1: CloudLinux kernel received an urgent security patch in "
                "5.14.0-687.60.1.el9_8."
            ),
            supporting_quotes=(
                "Paragraph 2: Update notes also confirm kernel-5.14.0-687.60.1.el9_8 "
                "fixes the flaw,",
            ),
        )
        res_ok = verify_quote_grounding(body, valid_multi, canonical_package_name="kernel")
        assert res_ok.status == GroundingStatus.VERIFIED

        context_supporting = ExtractedPackageClaim(
            raw_package_name="kernel",
            ecosystem="rpm",
            namespace="cloudlinux",
            version_constraints=(
                VersionConstraint(introduced="0", fixed="kernel-5.14.0-687.60.1.el9_8"),
            ),
            evidence_quote=(
                "Paragraph 1: CloudLinux kernel received an urgent security patch in "
                "5.14.0-687.60.1.el9_8."
            ),
            supporting_quotes=(
                "Paragraph 3: Unrelated note mentions requests library HTTP timeouts.",
            ),
        )
        res_ctx = verify_quote_grounding(body, context_supporting, canonical_package_name="kernel")
        assert res_ctx.status == GroundingStatus.VERIFIED

        fabricated_supporting = ExtractedPackageClaim(
            raw_package_name="kernel",
            ecosystem="rpm",
            namespace="cloudlinux",
            version_constraints=(VersionConstraint(fixed="5.14.0-687.60.1.el9_8"),),
            evidence_quote=(
                "Paragraph 1: CloudLinux kernel received an urgent security patch in "
                "5.14.0-687.60.1.el9_8."
            ),
            supporting_quotes=("Fabricated bullet claiming kernel 9.9.9 is vulnerable.",),
        )
        res_fab = verify_quote_grounding(
            body, fabricated_supporting, canonical_package_name="kernel"
        )
        assert res_fab.status == GroundingStatus.UNGROUNDED

        split_bait = ExtractedPackageClaim(
            raw_package_name="requests",
            ecosystem="pypi",
            version_constraints=(VersionConstraint(fixed="4.18.0-553.el8"),),
            evidence_quote="Paragraph 3: Unrelated note mentions requests library HTTP timeouts.",
            supporting_quotes=("whereas earlier branch 4.18.0-553.el8 remediated CL8.",),
        )
        res_split = verify_quote_grounding(body, split_bait, canonical_package_name="requests")
        assert res_split.status == GroundingStatus.QUOTE_ONLY_WEAK

    def test_flat_registry_namespace_stripping_and_distro_prefix_dedup(self) -> None:
        gem_res = resolve_purl("activesupport", ecosystem="gem", namespace="rubygems")
        assert gem_res.is_valid is True
        assert gem_res.namespace is None
        assert gem_res.canonical_purl == "pkg:gem/activesupport"

        cargo_res = resolve_purl("rustls", ecosystem="cargo", namespace="crates.io")
        assert cargo_res.is_valid is True
        assert cargo_res.namespace is None
        assert cargo_res.canonical_purl == "pkg:cargo/rustls"

        nuget_res = resolve_purl("Newtonsoft.Json", ecosystem="nuget", namespace="nuget")
        assert nuget_res.is_valid is True
        assert nuget_res.namespace is None
        assert nuget_res.canonical_purl == "pkg:nuget/Newtonsoft.Json"

        maven_echo = resolve_purl("jackson-databind", ecosystem="maven", namespace="maven")
        assert maven_echo.is_valid is True
        assert maven_echo.namespace is None
        assert maven_echo.canonical_purl == "pkg:maven/jackson-databind"

        go_promoted = resolve_purl("golang.org/x/crypto", ecosystem="generic")
        assert go_promoted.is_valid is True
        assert go_promoted.ecosystem == "golang"
        assert go_promoted.canonical_purl == "pkg:golang/golang.org/x/crypto"

        assert parse_osv_ecosystem("CloudLinux:cloudlinux-8") == ("CloudLinux", "cloudlinux-8")
        assert parse_osv_ecosystem("CloudLinux:el8") == ("CloudLinux", "cloudlinux-8")
        assert parse_osv_ecosystem("CloudLinux:el9_8") == ("CloudLinux", "cloudlinux-9")

    def test_audit_hardening_regressions_boundaries_caps_and_per_claim_quotes(self) -> None:
        # 1) Left-boundary guard rejects truncated version ("2.30.0" in "12.30.0") & package prefix
        #    ("requests" in "myrequests"), plus colon-list negation splicing.
        ver_claim = ExtractedPackageClaim(
            raw_package_name="requests",
            ecosystem="pypi",
            version_constraints=(VersionConstraint(fixed="2.30.0"),),
            evidence_quote="2.30.0 of requests is affected",
        )
        assert (
            verify_quote_grounding(
                "12.30.0 of requests is affected.",
                ver_claim,
                canonical_package_name="requests",
            ).status
            == GroundingStatus.UNGROUNDED
        )

        pkg_claim = ExtractedPackageClaim(
            raw_package_name="requests",
            ecosystem="pypi",
            version_constraints=(VersionConstraint(fixed="2.31.0"),),
            evidence_quote="requests prior to 2.31.0 is affected",
        )
        assert (
            verify_quote_grounding(
                "Package myrequests prior to 2.31.0 is affected.",
                pkg_claim,
                canonical_package_name="requests",
            ).status
            == GroundingStatus.UNGROUNDED
        )

        neg_body = (
            "Affected packages and timelines: foo-widget 1.0 (patched), bar-tool 2.0 (unaffected), "
            "requests 2.31.0 is the latest stable release"
        )
        neg_claim = ExtractedPackageClaim(
            raw_package_name="requests",
            ecosystem="pypi",
            version_constraints=(VersionConstraint(fixed="2.31.0"),),
            evidence_quote=(
                "Affected packages and timelines: requests 2.31.0 is the latest stable release"
            ),
        )
        assert (
            verify_quote_grounding(
                neg_body,
                neg_claim,
                canonical_package_name="requests",
            ).status
            == GroundingStatus.UNGROUNDED
        )

        # BiDi & soft-hyphen invisible chars strip cleanly for legitimate quotes.
        bidi_body = "Python requests\u00ad prior to\u202e 2.31.0 allows credential leaks."
        assert (
            verify_quote_grounding(
                bidi_body,
                ExtractedPackageClaim(
                    raw_package_name="requests",
                    ecosystem="pypi",
                    version_constraints=(VersionConstraint(fixed="2.31.0"),),
                    evidence_quote="Python requests prior to 2.31.0 allows credential leaks.",
                ),
                canonical_package_name="requests",
            ).status
            == GroundingStatus.VERIFIED
        )

        # 2) Cyrillic homoglyphs & pkg:generic/<ns>/utils fail closed.
        homoglyph = resolve_purl("ut\u0456ls", ecosystem="pypi")
        assert homoglyph.is_valid is False

        generic_ns = resolve_purl("utils", ecosystem="generic", namespace="internal")
        assert generic_ns.is_valid is False
        assert generic_ns.is_blocked_generic is True

        # 3) Unbounded zero-days + CWE/registry EXISTS and RegistryStatus.ERROR cap at <= 0.70.
        unbounded_body = "Python paramiko suffers from a remote flaw affecting all releases."
        unbounded_claim = ExtractedPackageClaim(
            raw_package_name="paramiko",
            ecosystem="pypi",
            version_constraints=(VersionConstraint(introduced="0", is_unbounded=True),),
            evidence_quote=unbounded_body,
        )
        unbounded_report = verify_advisory(
            _make_article(unbounded_body, source_tier=SourceTier.TIER_1),
            ExtractedAdvisory(
                article_url="https://security.example.org/paramiko-0day",
                title="Zero-day in paramiko",
                summary="Unbounded zero-day in paramiko",
                cwe_ids=("CWE-94",),
                claims=(unbounded_claim,),
            ),
        )
        assert unbounded_report.routing == RoutingDecision.TRIAGE
        assert unbounded_report.composite_score <= 0.70

        class _ErrChecker:
            def check(self, _purl: str) -> RegistryStatus:
                return RegistryStatus.ERROR

        err_body = "Python fake-unknown-pkg prior to 2.0.0 suffers from SSRF."
        err_report = verify_advisory(
            _make_article(err_body, source_tier=SourceTier.TIER_1),
            ExtractedAdvisory(
                article_url="https://security.example.org/reg-err",
                title="Registry error test",
                summary="Registry error cap test",
                cwe_ids=("CWE-918",),
                claims=(
                    ExtractedPackageClaim(
                        raw_package_name="fake-unknown-pkg",
                        ecosystem="pypi",
                        version_constraints=(VersionConstraint(fixed="2.0.0"),),
                        evidence_quote=err_body,
                    ),
                ),
            ),
            registry_checker=_ErrChecker(),
        )
        assert err_report.routing == RoutingDecision.TRIAGE
        assert err_report.composite_score <= 0.70

        # 4) Mixed AUTO + TRIAGE advisory compiles ONLY AUTO claims into the AUTO OSV.
        mixed_body = (
            "Python requests prior to 2.31.0 leaks credentials. "
            "In other news flask was discussed casually."
        )
        mixed_adv = ExtractedAdvisory(
            article_url="https://security.example.org/mixed-piggyback",
            title="Mixed routing",
            summary="Requests AUTO and flask TRIAGE",
            claims=(
                ExtractedPackageClaim(
                    raw_package_name="requests",
                    ecosystem="pypi",
                    version_constraints=(VersionConstraint(introduced="0", fixed="2.31.0"),),
                    evidence_quote="Python requests prior to 2.31.0 leaks credentials.",
                ),
                ExtractedPackageClaim(
                    raw_package_name="flask",
                    ecosystem="pypi",
                    version_constraints=(VersionConstraint(introduced="0", fixed="9.9.9"),),
                    evidence_quote="In other news flask was discussed casually.",
                ),
            ),
        )
        mixed_report = verify_advisory(_make_article(mixed_body), mixed_adv)
        assert mixed_report.routing == RoutingDecision.AUTO
        mixed_osv = compile_osv_advisory(mixed_adv, mixed_report, article=_make_article(mixed_body))
        assert mixed_osv is not None
        assert [a.package.purl for a in mixed_osv.affected] == ["pkg:pypi/requests"]
        assert mixed_osv.database_specific["zerobom"]["held_for_triage_purls"] == ["pkg:pypi/flask"]

        # 5) Invalid/inverted constraints skip hollow OsvAffected cleanly.
        inv_body = "Python urllib3 fixed in 2.2.2 since 1.26.0."
        inv_adv = ExtractedAdvisory(
            article_url="https://security.example.org/inverted-hollow",
            title="Inverted bounds",
            summary="Inverted bounds omit hollow OSV",
            claims=(
                ExtractedPackageClaim(
                    raw_package_name="urllib3",
                    ecosystem="pypi",
                    version_constraints=(VersionConstraint(introduced="2.2.2", fixed="1.26.0"),),
                    evidence_quote=inv_body,
                ),
            ),
        )
        inv_report = verify_advisory(_make_article(inv_body), inv_adv)
        assert inv_report.routing == RoutingDecision.TRIAGE
        assert compile_osv_advisory(inv_adv, inv_report) is None

        # 6) Multi-package OSV stores per-affected evidence quotes so matches carry their own quote.
        multi_body = (
            "Python requests versions prior to 2.31.0 leak secrets. "
            "PyPI urllib3 versions prior to 2.2.2 leak headers."
        )
        multi_adv = ExtractedAdvisory(
            article_url="https://security.example.org/multi-quote",
            title="Two bugs",
            summary="Two bugs",
            claims=(
                ExtractedPackageClaim(
                    raw_package_name="requests",
                    ecosystem="pypi",
                    version_constraints=(VersionConstraint(introduced="0", fixed="2.31.0"),),
                    evidence_quote="Python requests versions prior to 2.31.0 leak secrets.",
                ),
                ExtractedPackageClaim(
                    raw_package_name="urllib3",
                    ecosystem="pypi",
                    version_constraints=(VersionConstraint(introduced="0", fixed="2.2.2"),),
                    evidence_quote="PyPI urllib3 versions prior to 2.2.2 leak headers.",
                ),
            ),
        )
        multi_report = verify_advisory(_make_article(multi_body), multi_adv)
        multi_osv = compile_osv_advisory(multi_adv, multi_report)
        assert multi_osv is not None
        mr_u3 = evaluate_component_against_advisory(multi_osv, "pkg:pypi/urllib3", "2.2.0")
        assert mr_u3 is not None
        assert mr_u3.evidence_quote == "PyPI urllib3 versions prior to 2.2.2 leak headers."


class _ExistsChecker:
    """Minimal deterministic registry stub returning EXISTS for any queried PURL."""

    def check(self, purl: str) -> RegistryStatus:
        return RegistryStatus.EXISTS


class TestV011VerificationHardening:
    def test_requires_all_claimed_versions_in_quote(self) -> None:
        body = (
            "Node qs versions prior to 6.14.1 are affected. "
            "Older branches from 6.11.0 prior to 6.11.3 are also affected."
        )
        advisory = ExtractedAdvisory(
            article_url="https://security.example.org/qs-partial",
            title="qs partial quote",
            summary="qs partial quote",
            claims=(
                ExtractedPackageClaim(
                    raw_package_name="qs",
                    ecosystem="npm",
                    version_constraints=(
                        VersionConstraint(introduced="0", fixed="6.14.1"),
                        VersionConstraint(introduced="6.11.0", fixed="6.11.3"),
                    ),
                    evidence_quote="Node qs versions prior to 6.14.1 are affected.",
                ),
            ),
        )
        report = verify_advisory(_make_article(body), advisory, registry_checker=_ExistsChecker())
        assert report.routing == RoutingDecision.TRIAGE
        assert report.claim_results[0].grounding.status == GroundingStatus.QUOTE_ONLY_WEAK

        # Implied .0 branch origin verifies when only upper fix is quoted, while non-.0 doesn't.
        branch_body = "PHP released fixes in 8.5.12."
        implied_claim = ExtractedPackageClaim(
            raw_package_name="php",
            ecosystem="generic",
            version_constraints=(VersionConstraint(introduced="8.5.0", fixed="8.5.12"),),
            evidence_quote=branch_body,
        )
        assert verify_quote_grounding(branch_body, implied_claim).status == GroundingStatus.VERIFIED

        explicit_origin_claim = ExtractedPackageClaim(
            raw_package_name="php",
            ecosystem="generic",
            version_constraints=(VersionConstraint(introduced="8.5.1", fixed="8.5.12"),),
            evidence_quote=branch_body,
        )
        assert (
            verify_quote_grounding(branch_body, explicit_origin_claim).status
            == GroundingStatus.QUOTE_ONLY_WEAK
        )

    def test_rejects_fixed_zero_and_caps_quote_polarity_and_distro_claims(self) -> None:
        # 1) fixed="0" or last_affected="0" fails compilation without crash.
        body_zero = "Example pkg version 1.0.0 issue."
        adv_zero = ExtractedAdvisory(
            article_url="https://security.example.org/zero",
            title="Zero bound",
            summary="Zero bound",
            claims=(
                ExtractedPackageClaim(
                    raw_package_name="urllib3",
                    ecosystem="pypi",
                    version_constraints=(VersionConstraint(fixed="0"),),
                    evidence_quote=body_zero,
                ),
            ),
        )
        assert (
            compile_osv_advisory(adv_zero, verify_advisory(_make_article(body_zero), adv_zero))
            is None
        )

        # 2) Malicious compromise paired with `fixed` fails polarity check.
        mal_quote = (
            "Compromised npm package evil-helper version 1.0.2 executes postinstall malware."
        )
        mal_claim = ExtractedPackageClaim(
            raw_package_name="evil-helper",
            ecosystem="npm",
            version_constraints=(VersionConstraint(fixed="1.0.2"),),
            evidence_quote=mal_quote,
        )
        polarity_ok, polarity_reasons = check_quote_polarity(mal_claim)
        assert polarity_ok is False
        assert any("malicious" in r.lower() for r in polarity_reasons)

        # 3) Through / confirmed-against paired with `fixed` fails polarity check.
        incl_claim = ExtractedPackageClaim(
            raw_package_name="requests",
            ecosystem="pypi",
            version_constraints=(VersionConstraint(fixed="2.31.0"),),
            evidence_quote="Python requests through 2.31.0 allows token leak.",
        )
        incl_ok, _ = check_quote_polarity(incl_claim)
        assert incl_ok is False

        # 4) Copyright-only quote fails polarity check.
        banner_claim = ExtractedPackageClaim(
            raw_package_name="impacket",
            ecosystem="pypi",
            version_constraints=(VersionConstraint(exact="0.12.0"),),
            evidence_quote="Impacket v0.12.0 - Copyright Fortra 2024.",
        )
        banner_ok, _ = check_quote_polarity(banner_claim)
        assert banner_ok is False

        # 5) Upstream quote claimed as Debian distro without distro evidence fails distro grounding.
        upstream_claim = ExtractedPackageClaim(
            raw_package_name="openssl",
            ecosystem="deb",
            namespace="debian",
            version_constraints=(VersionConstraint(introduced="0", fixed="3.0.15"),),
            evidence_quote="Upstream OpenSSL prior to 3.0.15 leaks memory.",
        )
        distro_ok, _ = check_distro_quote_grounding(
            upstream_claim, ecosystem="deb", namespace="debian"
        )
        assert distro_ok is False

    def test_detects_overlapping_zero_introduced_branches_and_multi_claim_cap(self) -> None:
        has_overlap, reason = detect_overlapping_branch_ranges(
            "generic",
            (
                VersionConstraint(introduced="0", fixed="3.0.24"),
                VersionConstraint(introduced="0", fixed="4.1.1"),
            ),
            package_name="openssl",
        )
        assert has_overlap is True
        assert reason is not None

        # Separate claims targeting same PURL + ecosystem stream also cap to TRIAGE.
        body = (
            "OpenSSL 3.0 branch fixes issue prior to 3.0.24. "
            "OpenSSL 4.1 branch fixes issue prior to 4.1.1."
        )
        adv = ExtractedAdvisory(
            article_url="https://security.example.org/openssl-overlap",
            title="OpenSSL branches",
            summary="OpenSSL branches",
            claims=(
                ExtractedPackageClaim(
                    raw_package_name="openssl",
                    ecosystem="generic",
                    version_constraints=(VersionConstraint(introduced="0", fixed="3.0.24"),),
                    evidence_quote="OpenSSL 3.0 branch fixes issue prior to 3.0.24.",
                ),
                ExtractedPackageClaim(
                    raw_package_name="openssl",
                    ecosystem="generic",
                    version_constraints=(VersionConstraint(introduced="0", fixed="4.1.1"),),
                    evidence_quote="OpenSSL 4.1 branch fixes issue prior to 4.1.1.",
                ),
            ),
        )
        report = verify_advisory(_make_article(body), adv, registry_checker=_ExistsChecker())
        assert report.routing == RoutingDecision.TRIAGE

    def test_blocks_non_distro_rpm_apache_firmware_and_caps_article_types(self) -> None:
        # 1) pkg:rpm/apache/httpd is rejected by non-distro namespace blocklist.
        apache_purl = resolve_purl("httpd", "rpm", namespace="apache")
        assert apache_purl.is_valid is False

        # 2) Generic firmware token is blocked.
        fw_purl = resolve_purl("firmware", "generic")
        assert fw_purl.is_valid is False

        # 3) Delimiter `::` in package coordinate matches grounded body.
        col_claim = ExtractedPackageClaim(
            raw_package_name="Net::HTTP",
            ecosystem="gem",
            version_constraints=(VersionConstraint(introduced="0", fixed="0.4.1"),),
            evidence_quote="Ruby Net::HTTP prior to 0.4.1 leaks credentials.",
        )
        col_res = verify_quote_grounding(
            "Ruby Net::HTTP prior to 0.4.1 leaks credentials.",
            col_claim,
        )
        assert col_res.status == GroundingStatus.VERIFIED

        # 4) Non-vulnerability / offensive / product / benchmark ArticleType -> DROP.
        good_body = "Python requests versions prior to 2.31.0 leak credentials."
        drop_adv = ExtractedAdvisory(
            article_url="https://security.example.org/offensive",
            title="Red team guide",
            summary="Red team guide",
            article_type=ArticleType.OFFENSIVE_TECHNIQUE,
            claims=(
                ExtractedPackageClaim(
                    raw_package_name="requests",
                    ecosystem="pypi",
                    version_constraints=(VersionConstraint(introduced="0", fixed="2.31.0"),),
                    evidence_quote=good_body,
                ),
            ),
        )
        drop_report = verify_advisory(
            _make_article(good_body), drop_adv, registry_checker=_ExistsChecker()
        )
        assert drop_report.routing == RoutingDecision.DROP
        assert compile_osv_advisory(drop_adv, drop_report) is None

        # 5) Secondary known_vuln_analysis ArticleType -> capped to TRIAGE.
        triage_adv = drop_adv.model_copy(update={"article_type": ArticleType.KNOWN_VULN_ANALYSIS})
        triage_report = verify_advisory(
            _make_article(good_body), triage_adv, registry_checker=_ExistsChecker()
        )
        assert triage_report.routing == RoutingDecision.TRIAGE
        compiled = compile_osv_advisory(triage_adv, triage_report)
        assert compiled is not None
        assert compiled.affected[0].database_specific["zerobom"]["routing"] == "triage"

    def test_github_purl_and_expanded_registry_checker(self) -> None:
        gh_res = resolve_purl("aquasecurity/trivy", "github", namespace="aquasecurity")
        assert gh_res.is_valid is True
        assert gh_res.canonical_purl == "pkg:github/aquasecurity/trivy"

        seen_urls: list[str] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            seen_urls.append(str(request.url))
            return httpx.Response(200, json={"ok": True})

        with httpx.Client(transport=httpx.MockTransport(_handler)) as client:
            checker = HttpRegistryChecker(client=client)
            assert checker.check("pkg:cargo/serde") == RegistryStatus.EXISTS
            assert checker.check("pkg:gem/rails") == RegistryStatus.EXISTS
            assert checker.check("pkg:nuget/Newtonsoft.Json") == RegistryStatus.EXISTS
            assert checker.check("pkg:composer/symfony/http-kernel") == RegistryStatus.EXISTS

        assert "https://crates.io/api/v1/crates/serde" in seen_urls
        assert "https://rubygems.org/api/v1/gems/rails.json" in seen_urls
        assert "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json" in seen_urls
        assert "https://repo.packagist.org/p2/symfony/http-kernel.json" in seen_urls

    def test_osv_hard_auto_gate_drops_unbounded_claims(self) -> None:
        # Claim with valid unbounded package + bounded verified claim: AUTO compiles only bounded!
        body = (
            "Python requests prior to 2.31.0 is vulnerable. "
            "PyPI urllib3 was also mentioned without fixed versions."
        )
        adv = ExtractedAdvisory(
            article_url="https://security.example.org/mixed-auto",
            title="Mixed bounds",
            summary="Mixed bounds",
            claims=(
                ExtractedPackageClaim(
                    raw_package_name="requests",
                    ecosystem="pypi",
                    version_constraints=(VersionConstraint(introduced="0", fixed="2.31.0"),),
                    evidence_quote="Python requests prior to 2.31.0 is vulnerable.",
                    claim_aliases=("CVE-2026-88888",),
                ),
                ExtractedPackageClaim(
                    raw_package_name="urllib3",
                    ecosystem="pypi",
                    version_constraints=(),
                    evidence_quote="PyPI urllib3 was also mentioned without fixed versions.",
                ),
            ),
        )
        report = verify_advisory(_make_article(body), adv, registry_checker=_ExistsChecker())
        assert report.routing == RoutingDecision.AUTO
        osv_doc = compile_osv_advisory(adv, report)
        assert osv_doc is not None
        assert len(osv_doc.affected) == 1
        assert osv_doc.affected[0].package.name == "requests"
        assert "CVE-2026-88888" in osv_doc.aliases
        assert osv_doc.affected[0].database_specific["zerobom"]["routing"] == "auto"
