"""Comprehensive offline unit tests for pipeline, outputs (JSON/SARIF/Rich), and CLI."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Any

import httpx
import pytest
from rich.console import Console
from typer.testing import CliRunner

from zerobom import cli
from zerobom.backends import BackendQueryError, LocalSbomBackend
from zerobom.extract import ExtractionError, OpenAICompatConfig, OpenAICompatExtractor
from zerobom.ingest import IngestStateStore, SafeHttpFetcher
from zerobom.models import (
    AssetRef,
    ExtractedAdvisory,
    ExtractedPackageClaim,
    FeedKind,
    InventoryComponent,
    OsvAdvisory,
    OsvAffected,
    OsvPackage,
    OsvRange,
    OsvRangeEvent,
    PackageQuery,
    PipelineOutcome,
    RawArticle,
    RoutingDecision,
    SourceFeedConfig,
    SourceTier,
    VersionConstraint,
)
from zerobom.outputs import (
    build_json_report,
    build_sarif_log,
    render_terminal_outcomes,
)
from zerobom.pipeline import load_osv_advisories, process_article, watch_feeds

PUBLISHED_AT = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
RUNNER = CliRunner()


def _public_dns(_host: str, _port: int) -> tuple[str, ...]:
    return ("93.184.216.34",)


def _write_json(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


class _StaticTestExtractor:
    def __init__(self, advisory: ExtractedAdvisory) -> None:
        self._advisory = advisory

    @property
    def model_name(self) -> str:
        return "test-static-model"

    @property
    def prompt_version(self) -> str:
        return "v1.0"

    def extract(self, article: RawArticle, *, known_aliases: Any = ()) -> ExtractedAdvisory:
        del article, known_aliases
        return self._advisory


# ---------------------------------------------------------------------------
# 1. Pipeline & OSV Loader Tests
# ---------------------------------------------------------------------------


class TestPipelineOrchestration:
    def test_triage_gating_respects_query_on_triage_flag(self, tmp_path: Path) -> None:
        # UNKNOWN source tier caps perfect extraction at 0.55 -> TRIAGE.
        article = RawArticle(
            url="https://unknown.example.org/post",
            title="SSRF in requests",
            body="Vulnerability in Python requests prior to 2.31.0 leaks credentials.",
            source_name="Unknown Blog",
            source_tier=SourceTier.UNKNOWN,
            published_at=PUBLISHED_AT,
        )
        advisory = ExtractedAdvisory(
            article_url=article.url,
            title=article.title,
            summary="SSRF in requests < 2.31.0",
            claims=(
                ExtractedPackageClaim(
                    raw_package_name="Python requests",
                    ecosystem="pypi",
                    version_constraints=(VersionConstraint(introduced="0", fixed="2.31.0"),),
                    evidence_quote="Python requests prior to 2.31.0 leaks credentials",
                ),
            ),
            cwe_ids=("CWE-918",),
        )
        sbom_path = _write_json(
            tmp_path / "app.cdx.json",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "type": "library",
                        "name": "requests",
                        "version": "2.30.0",
                        "purl": "pkg:pypi/requests@2.30.0",
                    }
                ],
            },
        )
        backend = LocalSbomBackend(sbom_path)
        extractor = _StaticTestExtractor(advisory)

        # Default query_on_triage=False does NOT query backend on TRIAGE.
        out_skip = process_article(article, extractor=extractor, backend=backend)
        assert out_skip.credibility is not None
        assert out_skip.credibility.routing.value == "triage"
        assert out_skip.matches == ()

        # query_on_triage=True queries backend and surfaces match.
        out_query = process_article(
            article,
            extractor=extractor,
            backend=backend,
            query_on_triage=True,
        )
        assert len(out_query.matches) == 1
        assert out_query.matches[0].is_vulnerable is True

    def test_load_osv_advisories_directory_and_guards(self, tmp_path: Path) -> None:
        osv_dir = tmp_path / "osv"
        adv = OsvAdvisory(
            id="PRECVE-2026-11223344",
            modified=PUBLISHED_AT,
            published=PUBLISHED_AT,
            summary="Requests SSRF",
            affected=(
                OsvAffected(
                    package=OsvPackage(ecosystem="PyPI", name="requests", purl="pkg:pypi/requests"),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(OsvRangeEvent(introduced="0"), OsvRangeEvent(fixed="2.31.0")),
                        ),
                    ),
                ),
            ),
        )
        osv_file = osv_dir / "adv1.json"
        _write_json(osv_file, adv.to_osv_dict())

        loaded = load_osv_advisories(osv_dir)
        assert len(loaded) == 1
        assert loaded[0].id == "PRECVE-2026-11223344"

        with pytest.raises(ValueError, match="maximum allowed size"):
            load_osv_advisories(osv_file, max_file_bytes=10)

        bad_file = tmp_path / "bad_osv.json"
        bad_file.write_text("{invalid", encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid OSV JSON"):
            load_osv_advisories(bad_file)


# ---------------------------------------------------------------------------
# 2. Output Formatters (SARIF 2.1.0, JSON, Rich Markup Safety)
# ---------------------------------------------------------------------------


class TestOutputs:
    def test_terminal_renderer_resists_rich_markup_injection(self) -> None:
        malicious_title = "[/bold][red]INJECTED_TAG[/red]"
        malicious_quote = "requests prior to 2.31.0 [blink]FAKE_MARKUP[/blink] bug"
        article = RawArticle(
            url="https://example.org/xss",
            title=malicious_title,
            body=malicious_quote,
            source_name="[bold]EvilSource[/bold]",
            source_tier=SourceTier.TIER_1,
            published_at=PUBLISHED_AT,
        )
        outcome = PipelineOutcome(
            article=article,
            skipped_reason="Dropped [/panel][red]payload",
        )
        buf = StringIO()
        console = Console(file=buf, no_color=True, width=120)
        render_terminal_outcomes((outcome,), console=console)
        rendered = buf.getvalue()
        assert "[/bold][red]INJECTED_TAG[/red]" in rendered
        assert "[bold]EvilSource[/bold]" in rendered
        assert "Dropped [/panel][red]payload" in rendered

    def test_terminal_renderer_deduplicates_quotes_and_shows_affected_summary(self) -> None:
        shared_quote = "PHP released fixes in versions 8.5.12, 8.4.27, 8.3.36 and 8.2.35."
        body = (
            f"{shared_quote} Hosts running php should upgrade immediately. "
            "CloudLinux 9 also backported kernel-5.14.0-687.60.1.el9_8."
        )
        article = RawArticle(
            url="https://tenable.example.org/blog/php2shell",
            title="php2shell (CVE-2026-109618, CVE-2026-109619)",
            body=body,
            source_name="Manual URL",
            source_tier=SourceTier.TIER_1,
            published_at=PUBLISHED_AT,
        )
        advisory = ExtractedAdvisory(
            article_url=article.url,
            title=article.title,
            summary="Multi-branch PHP RCE plus CloudLinux 9 kernel stream entry.",
            known_aliases=("CVE-2026-109618", "CVE-2026-109619"),
            claims=(
                ExtractedPackageClaim(
                    raw_package_name="php",
                    ecosystem="generic",
                    version_constraints=(VersionConstraint(introduced="8.5.0", fixed="8.5.12"),),
                    evidence_quote=shared_quote,
                ),
                ExtractedPackageClaim(
                    raw_package_name="php",
                    ecosystem="generic",
                    version_constraints=(VersionConstraint(introduced="8.4.0", fixed="8.4.27"),),
                    evidence_quote=shared_quote,
                ),
                ExtractedPackageClaim(
                    raw_package_name="php",
                    ecosystem="generic",
                    version_constraints=(VersionConstraint(introduced="8.3.0", fixed="8.3.36"),),
                    evidence_quote=shared_quote,
                ),
                ExtractedPackageClaim(
                    raw_package_name="php",
                    ecosystem="generic",
                    version_constraints=(VersionConstraint(introduced="8.2.0", fixed="8.2.35"),),
                    evidence_quote=shared_quote,
                ),
                ExtractedPackageClaim(
                    raw_package_name="kernel",
                    ecosystem="rpm",
                    namespace="cloudlinux",
                    distro_release="9",
                    version_constraints=(
                        VersionConstraint(introduced="0", fixed="kernel-5.14.0-687.60.1.el9_8"),
                    ),
                    evidence_quote="CloudLinux 9 also backported kernel-5.14.0-687.60.1.el9_8.",
                ),
            ),
        )
        outcome = process_article(article, extractor=_StaticTestExtractor(advisory))
        buf = StringIO()
        console = Console(file=buf, no_color=True, width=160)
        render_terminal_outcomes((outcome,), console=console)
        rendered = buf.getvalue()

        assert rendered.count(shared_quote) == 1
        assert rendered.count("Verified Quote:") == 2
        assert "Aliases: CVE-2026-109618, CVE-2026-109619" in rendered
        assert "Affected: pkg:generic/php" in rendered
        for fixed_ver in ("<8.5.12", "<8.4.27", "<8.3.36", "<8.2.35"):
            assert fixed_ver in rendered
        assert "Affected: pkg:rpm/cloudlinux/kernel [CloudLinux:9]" in rendered


# ---------------------------------------------------------------------------
# 3. CLI Commands (demo, scan, check, watch, backends)
# ---------------------------------------------------------------------------


class TestCliCommands:
    def test_cli_demo_terminal_json_and_sarif_outputs(self, tmp_path: Path) -> None:
        # 1) Terminal format -> exit 0
        res_term = RUNNER.invoke(cli.app, ["demo"])
        assert res_term.exit_code == 0
        assert "PRECVE-" in res_term.stdout
        assert "pkg:pypi/requests" in res_term.stdout
        assert "pkg:deb/debian/openssl" in res_term.stdout
        assert "Dropped Claim: utils" in res_term.stdout

        # 2) JSON format -> exit 0, valid schema, 2 vulnerable hits
        res_json = RUNNER.invoke(cli.app, ["demo", "--format", "json"])
        assert res_json.exit_code == 0
        report = json.loads(res_json.stdout)
        assert report["schema"] == "zerobom.report/v1"
        assert report["summary"]["auto_count"] == 1
        assert report["summary"]["vulnerable_hits"] == 2
        assert len(report["results"][0]["credibility"]["dropped_claims"]) == 1

        # 3) SARIF 2.1.0 format -> GitHub Code Scanning compliant & deterministic fingerprints
        sarif_out = tmp_path / "demo.sarif"
        res_sarif_1 = RUNNER.invoke(
            cli.app,
            ["demo", "--format", "sarif", "--output", str(sarif_out)],
        )
        assert res_sarif_1.exit_code == 0
        sarif_1 = json.loads(sarif_out.read_text(encoding="utf-8"))
        assert sarif_1["version"] == "2.1.0"
        run = sarif_1["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        results = run["results"]
        assert len(rules) == 1
        assert rules[0]["properties"]["security-severity"] == "7.5"
        assert "helpUri" in rules[0]
        assert len(results) == 2
        for result in results:
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            assert "\\" not in uri
            assert ":" not in uri
            assert "primaryLocationLineHash" in result["partialFingerprints"]

        res_sarif_2 = RUNNER.invoke(cli.app, ["demo", "--format", "sarif"])
        sarif_2 = json.loads(res_sarif_2.stdout)
        assert (
            sarif_1["runs"][0]["results"][0]["partialFingerprints"]
            == sarif_2["runs"][0]["results"][0]["partialFingerprints"]
        )

    def test_cli_scan_exit_codes_and_output(self, tmp_path: Path) -> None:
        adv = OsvAdvisory(
            id="PRECVE-2026-AABB1122",
            modified=PUBLISHED_AT,
            published=PUBLISHED_AT,
            summary="Requests SSRF",
            affected=(
                OsvAffected(
                    package=OsvPackage(ecosystem="PyPI", name="requests", purl="pkg:pypi/requests"),
                    ranges=(
                        OsvRange(
                            type="ECOSYSTEM",
                            events=(OsvRangeEvent(introduced="0"), OsvRangeEvent(fixed="2.31.0")),
                        ),
                    ),
                ),
            ),
        )
        osv_path = _write_json(tmp_path / "adv.json", adv.to_osv_dict())
        vuln_sbom = _write_json(
            tmp_path / "vuln.cdx.json",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "type": "library",
                        "name": "requests",
                        "version": "2.30.0",
                        "purl": "pkg:pypi/requests@2.30.0",
                    }
                ],
            },
        )
        clean_sbom = _write_json(
            tmp_path / "clean.cdx.json",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "type": "library",
                        "name": "requests",
                        "version": "2.31.0",
                        "purl": "pkg:pypi/requests@2.31.0",
                    }
                ],
            },
        )

        # Vulnerable SBOM -> exit 1
        out_json = tmp_path / "scan.json"
        res_vuln = RUNNER.invoke(
            cli.app,
            [
                "scan",
                "--osv",
                str(osv_path),
                "--sbom",
                str(vuln_sbom),
                "--format",
                "json",
                "--output",
                str(out_json),
            ],
        )
        assert res_vuln.exit_code == cli.EXIT_VULNERABLE
        assert json.loads(out_json.read_text(encoding="utf-8"))["summary"]["vulnerable_hits"] == 1

        # --no-fail-on-hits -> exit 0 even with hits
        res_no_fail = RUNNER.invoke(
            cli.app,
            [
                "scan",
                "--osv",
                str(osv_path),
                "--sbom",
                str(vuln_sbom),
                "--no-fail-on-hits",
            ],
        )
        assert res_no_fail.exit_code == cli.EXIT_OK

        # Patched SBOM -> exit 0
        res_clean = RUNNER.invoke(
            cli.app,
            ["scan", "--osv", str(osv_path), "--sbom", str(clean_sbom)],
        )
        assert res_clean.exit_code == cli.EXIT_OK

        # Missing --sbom for local_sbom -> exit 2
        res_missing_sbom = RUNNER.invoke(cli.app, ["scan", "--osv", str(osv_path)])
        assert res_missing_sbom.exit_code == cli.EXIT_ERROR

        # Missing OSV path -> exit 2
        res_missing_osv = RUNNER.invoke(
            cli.app,
            ["scan", "--osv", str(tmp_path / "nope.json"), "--sbom", str(clean_sbom)],
        )
        assert res_missing_osv.exit_code == cli.EXIT_ERROR

    def test_cli_check_and_watch_with_mocked_http_and_llm(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        vuln_html = (
            b"<html><head><title>Requests Bug</title></head>"
            b"<body><article><p>SSRF vulnerability affects Python requests prior to 2.31.0."
            b"</p></article></body></html>"
        )
        promo_html = (
            b"<html><head><title>Webinar Promo</title></head>"
            b"<body><article><p>Register now for our live webinar and visit our RSA booth!"
            b"</p></article></body></html>"
        )
        rss_xml = b"""<?xml version="1.0"?>
        <rss version="2.0"><channel><title>SecFeed</title>
          <item><title>Requests Bug</title><link>https://blog.example.org/vuln</link></item>
        </channel></rss>"""

        def web_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if url == "https://blog.example.org/rss.xml":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/xml"},
                    content=rss_xml,
                )
            if url == "https://blog.example.org/vuln":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "text/html", "ETag": '"v1"'},
                    content=vuln_html,
                )
            if url == "https://blog.example.org/promo":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "text/html"},
                    content=promo_html,
                )
            return httpx.Response(404)

        llm_payload = {
            "title": "Requests SSRF",
            "summary": "SSRF in Python requests < 2.31.0",
            "severity": "HIGH",
            "claims": [
                {
                    "raw_package_name": "Python requests",
                    "ecosystem": "pypi",
                    "version_constraints": [{"introduced": "0", "fixed": "2.31.0"}],
                    "evidence_quote": "Python requests prior to 2.31.0",
                }
            ],
        }

        def llm_handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": json.dumps(llm_payload)}}]},
            )

        monkeypatch.setattr(
            cli,
            "_create_fetcher",
            lambda: SafeHttpFetcher(
                client=httpx.Client(transport=httpx.MockTransport(web_handler)),
                dns_resolver=_public_dns,
            ),
        )
        monkeypatch.setattr(
            cli,
            "_create_extractor",
            lambda: OpenAICompatExtractor(
                OpenAICompatConfig(model="mock-llm"),
                client=httpx.Client(transport=httpx.MockTransport(llm_handler)),
            ),
        )

        sbom_path = _write_json(
            tmp_path / "sboms" / "app.cdx.json",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "type": "library",
                        "name": "requests",
                        "version": "2.30.0",
                        "purl": "pkg:pypi/requests@2.30.0",
                    }
                ],
            },
        )

        # check vuln URL -> exit 1
        res_check_hit = RUNNER.invoke(
            cli.app,
            [
                "check",
                "--url",
                "https://blog.example.org/vuln",
                "--sbom",
                str(sbom_path),
                "--tier",
                "tier_1",
                "--format",
                "json",
            ],
        )
        assert res_check_hit.exit_code == cli.EXIT_VULNERABLE
        assert json.loads(res_check_hit.stdout)["summary"]["vulnerable_hits"] == 1

        # check promo URL -> dropped by prefilter -> exit 0
        res_check_promo = RUNNER.invoke(
            cli.app,
            [
                "check",
                "--url",
                "https://blog.example.org/promo",
                "--sbom",
                str(sbom_path),
                "--format",
                "json",
            ],
        )
        assert res_check_promo.exit_code == cli.EXIT_OK
        assert json.loads(res_check_promo.stdout)["results"][0]["skipped_reason"] is not None

        # check SSRF URL -> exit 2
        res_ssrf = RUNNER.invoke(
            cli.app,
            ["check", "--url", "http://169.254.169.254/latest/meta-data/"],
        )
        assert res_ssrf.exit_code == cli.EXIT_ERROR

        # watch first poll -> exit 1; second poll -> unchanged -> exit 0
        feeds_yaml = tmp_path / "feeds.yaml"
        feeds_yaml.write_text(
            "version: 1\nfeeds:\n"
            '  - name: "SecFeed"\n'
            '    url: "https://blog.example.org/rss.xml"\n'
            '    tier: "tier_1"\n',
            encoding="utf-8",
        )
        state_db = tmp_path / "watch_state.sqlite"

        res_watch_1 = RUNNER.invoke(
            cli.app,
            [
                "watch",
                "--feeds",
                str(feeds_yaml),
                "--sbom-dir",
                str(sbom_path.parent),
                "--state-db",
                str(state_db),
                "--format",
                "json",
            ],
        )
        assert res_watch_1.exit_code == cli.EXIT_VULNERABLE
        assert json.loads(res_watch_1.stdout)["summary"]["vulnerable_hits"] == 1

        res_watch_2 = RUNNER.invoke(
            cli.app,
            [
                "watch",
                "--feeds",
                str(feeds_yaml),
                "--sbom-dir",
                str(sbom_path.parent),
                "--state-db",
                str(state_db),
                "--format",
                "json",
            ],
        )
        assert res_watch_2.exit_code == cli.EXIT_OK
        assert json.loads(res_watch_2.stdout)["summary"]["total_analyzed"] == 0

    def test_cli_backends_and_helper_outputs(self) -> None:
        res = RUNNER.invoke(cli.app, ["backends"])
        assert res.exit_code == 0
        assert "local_sbom" in res.stdout

        # Empty SARIF / JSON report builds cleanly
        empty_json = build_json_report(())
        assert empty_json["summary"]["total_analyzed"] == 0
        empty_sarif = build_sarif_log(())
        assert empty_sarif["runs"][0]["results"] == []
        assert empty_sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_watch_feeds_retries_after_transient_extraction_failure_and_persists_etag(
        self,
        tmp_path: Path,
    ) -> None:
        rss_xml = b"""<?xml version="1.0"?>
        <rss version="2.0"><channel><title>Feed</title>
          <item><title>Requests SSRF</title><link>https://blog.example.org/requests-ssrf</link></item>
        </channel></rss>"""
        body = b"Security advisory: Python requests versions prior to 2.31.0 leak credentials."
        poll_phase = [1]

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if url == "https://blog.example.org/rss.xml":
                return httpx.Response(
                    200, headers={"Content-Type": "application/xml"}, content=rss_xml
                )
            if url == "https://blog.example.org/requests-ssrf":
                if poll_phase[0] == 3:
                    assert request.headers.get("if-none-match") == '"etag-1"'
                    return httpx.Response(304, headers={"ETag": '"etag-1"'})
                return httpx.Response(
                    200,
                    headers={"Content-Type": "text/plain", "ETag": '"etag-1"'},
                    content=body,
                )
            return httpx.Response(404)

        class _TransientThenOkExtractor:
            model_name = "mock-retry"
            prompt_version = "v1.1"

            def __init__(self) -> None:
                self.calls = 0

            def extract(self, article: RawArticle, *, known_aliases: Any = ()) -> ExtractedAdvisory:
                del known_aliases
                self.calls += 1
                if self.calls == 1:
                    raise ExtractionError("Simulated LLM 503 during initial watch")
                return ExtractedAdvisory(
                    article_url=article.url,
                    title=article.title,
                    summary="Requests SSRF < 2.31.0",
                    claims=(
                        ExtractedPackageClaim(
                            raw_package_name="requests",
                            ecosystem="pypi",
                            version_constraints=(
                                VersionConstraint(introduced="0", fixed="2.31.0"),
                            ),
                            evidence_quote=(
                                "Python requests versions prior to 2.31.0 leak credentials."
                            ),
                        ),
                    ),
                )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        fetcher = SafeHttpFetcher(client=client, dns_resolver=_public_dns)
        store = IngestStateStore(tmp_path / "watch_retry.sqlite")
        extractor = _TransientThenOkExtractor()
        feeds = (
            SourceFeedConfig(
                name="Blog Feed",
                url="https://blog.example.org/rss.xml",
                tier=SourceTier.TIER_1,
            ),
        )

        # Poll 1: extraction fails -> state_store remains empty (article stays retriable).
        with pytest.raises(ExtractionError, match="503"):
            watch_feeds(feeds, fetcher=fetcher, extractor=extractor, state_store=store)
        assert store.count() == 0

        # Poll 2: extraction succeeds -> article marked seen with ETag, advisory ID, and AUTO route.
        poll_phase[0] = 2
        outcomes = watch_feeds(feeds, fetcher=fetcher, extractor=extractor, state_store=store)
        assert len(outcomes) == 1
        assert store.count() == 1
        record = store.get("https://blog.example.org/requests-ssrf")
        assert record is not None
        assert record.etag == '"etag-1"'
        assert record.advisory_id is not None and record.advisory_id.startswith("PRECVE-")
        assert record.routing == RoutingDecision.AUTO

        # Poll 3: persisted ETag drives 304 Not Modified without invoking extractor again.
        poll_phase[0] = 3
        outcomes_3 = watch_feeds(feeds, fetcher=fetcher, extractor=extractor, state_store=store)
        assert outcomes_3 == ()
        assert extractor.calls == 2
        client.close()

    def test_watch_feeds_supports_sitemap_and_html_index_sources(self, tmp_path: Path) -> None:
        sitemap_xml = b"""<?xml version="1.0"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url>
            <loc>https://vendor.example.org/blog/requests-advisory</loc>
            <lastmod>2026-11-18</lastmod>
          </url>
          <url>
            <loc>https://vendor.example.org/pricing</loc>
            <lastmod>2026-11-18</lastmod>
          </url>
        </urlset>"""
        index_html = b"""<!DOCTYPE html>
        <html><body>
          <a href="/security/lodash-proto">Lodash Prototype Pollution Advisory</a>
          <a href="/company/about">About Us</a>
        </body></html>"""

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if url == "https://vendor.example.org/sitemap.xml":
                return httpx.Response(
                    200, headers={"Content-Type": "application/xml"}, content=sitemap_xml
                )
            if url == "https://vendor.example.org/blog/requests-advisory":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "text/plain"},
                    content=b"Vulnerability in PyPI requests prior to 2.31.0.",
                )
            if url == "https://blog.example.org/security/":
                return httpx.Response(
                    200, headers={"Content-Type": "text/html"}, content=index_html
                )
            if url == "https://blog.example.org/security/lodash-proto":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "text/plain"},
                    content=b"Prototype pollution in npm lodash prior to 4.17.21.",
                )
            return httpx.Response(404)

        class _MultiSourceMockExtractor:
            model_name = "mock-multi"
            prompt_version = "v1.1"

            def extract(self, article: RawArticle, *, known_aliases: Any = ()) -> ExtractedAdvisory:
                del known_aliases
                if "requests" in article.url:
                    claim = ExtractedPackageClaim(
                        raw_package_name="requests",
                        ecosystem="pypi",
                        version_constraints=(VersionConstraint(introduced="0", fixed="2.31.0"),),
                        evidence_quote="Vulnerability in PyPI requests prior to 2.31.0.",
                    )
                else:
                    claim = ExtractedPackageClaim(
                        raw_package_name="lodash",
                        ecosystem="npm",
                        version_constraints=(VersionConstraint(introduced="0", fixed="4.17.21"),),
                        evidence_quote="Prototype pollution in npm lodash prior to 4.17.21.",
                    )
                return ExtractedAdvisory(
                    article_url=article.url,
                    title=article.title,
                    summary=article.title,
                    claims=(claim,),
                )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        fetcher = SafeHttpFetcher(client=client, dns_resolver=_public_dns)
        store = IngestStateStore(tmp_path / "multi_source.sqlite")
        feeds = (
            SourceFeedConfig(
                name="Vendor Sitemap",
                url="https://vendor.example.org/sitemap.xml",
                tier=SourceTier.TIER_1,
                kind=FeedKind.SITEMAP,
                url_prefix="https://vendor.example.org/blog",
            ),
            SourceFeedConfig(
                name="Html Blog",
                url="https://blog.example.org/security/",
                tier=SourceTier.TIER_1,
                kind=FeedKind.HTML_INDEX,
                url_prefix="https://blog.example.org/security/",
            ),
        )

        outcomes = watch_feeds(
            feeds,
            fetcher=fetcher,
            extractor=_MultiSourceMockExtractor(),
            state_store=store,
        )
        client.close()
        assert len(outcomes) == 2
        purls = {
            outcomes[0].osv.affected[0].package.purl,  # type: ignore[union-attr]
            outcomes[1].osv.affected[0].package.purl,  # type: ignore[union-attr]
        }
        assert purls == {"pkg:pypi/requests", "pkg:npm/lodash"}
        assert store.count() == 2

    def test_cli_backend_options_config_close_cleanup_and_error_exit(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sbom_path = _write_json(
            tmp_path / "sboms" / "app.cdx.json",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "type": "library",
                        "name": "requests",
                        "version": "2.30.0",
                        "purl": "pkg:pypi/requests@2.30.0",
                    }
                ],
            },
        )
        osv_path = _write_json(
            tmp_path / "adv.json",
            OsvAdvisory(
                id="PRECVE-2026-99887766",
                modified=PUBLISHED_AT,
                published=PUBLISHED_AT,
                summary="Requests SSRF",
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
            ).to_osv_dict(),
        )

        # 1) --backend-config + --backend-opt + close() cleanup verified on scan
        closed_flags: list[bool] = []
        seen_configs: list[dict[str, Any]] = []

        class _ClosableMockBackend:
            name = "closable_mock"

            @classmethod
            def from_config(cls, config: dict[str, Any]) -> _ClosableMockBackend:
                seen_configs.append(dict(config))
                return cls()

            def find_components(
                self, queries: list[PackageQuery]
            ) -> tuple[InventoryComponent, ...]:
                del queries
                return (
                    InventoryComponent(
                        name="requests",
                        version="2.30.0",
                        purl="pkg:pypi/requests@2.30.0",
                        canonical_purl="pkg:pypi/requests",
                        ecosystem="pypi",
                        asset=AssetRef(
                            asset_id="mock://asset-1",
                            asset_type="sbom",
                            backend="closable_mock",
                        ),
                    ),
                )

            def close(self) -> None:
                closed_flags.append(True)

        class _PatchedRegistry(cli.BackendRegistry):
            def __init__(self) -> None:
                super().__init__()
                self.register("closable_mock", _ClosableMockBackend)

        monkeypatch.setattr(cli, "BackendRegistry", _PatchedRegistry)

        cfg_file = tmp_path / "backend.yaml"
        cfg_file.write_text("url: https://inv.internal\nscope: prod\n", encoding="utf-8")

        res_scan = RUNNER.invoke(
            cli.app,
            [
                "scan",
                "--osv",
                str(osv_path),
                "--backend",
                "closable_mock",
                "--backend-config",
                str(cfg_file),
                "--backend-opt",
                "scope=staging",
                "--format",
                "json",
            ],
        )
        assert res_scan.exit_code == cli.EXIT_VULNERABLE
        assert seen_configs[0]["url"] == "https://inv.internal"
        assert seen_configs[0]["scope"] == "staging"
        assert closed_flags == [True]

        # 2) Runtime BackendQueryError returns EXIT_ERROR = 2 cleanly without unhandled traceback.
        class _FailingQueryBackend:
            name = "failing_mock"

            @classmethod
            def from_config(cls, config: dict[str, Any]) -> _FailingQueryBackend:
                del config
                return cls()

            def find_components(
                self, queries: list[PackageQuery]
            ) -> tuple[InventoryComponent, ...]:
                del queries
                raise BackendQueryError("Upstream API returned HTTP 401")

            def close(self) -> None:
                closed_flags.append(True)

        class _FailingRegistry(cli.BackendRegistry):
            def __init__(self) -> None:
                super().__init__()
                self.register("failing_mock", _FailingQueryBackend)

        monkeypatch.setattr(cli, "BackendRegistry", _FailingRegistry)
        res_fail = RUNNER.invoke(
            cli.app,
            ["scan", "--osv", str(osv_path), "--backend", "failing_mock"],
        )
        assert res_fail.exit_code == cli.EXIT_ERROR
        assert "HTTP 401" in res_fail.output
        assert closed_flags == [True, True]

        # 3) --sbom and --sbom-dir on watch cannot be combined, and --sbom alias works.
        monkeypatch.undo()
        feeds_yaml = tmp_path / "empty_feeds.yaml"
        feeds_yaml.write_text("version: 1\nfeeds: []\n", encoding="utf-8")

        res_both = RUNNER.invoke(
            cli.app,
            [
                "watch",
                "--feeds",
                str(feeds_yaml),
                "--sbom",
                str(sbom_path),
                "--sbom-dir",
                str(sbom_path.parent),
            ],
        )
        assert res_both.exit_code == cli.EXIT_ERROR

        res_alias = RUNNER.invoke(
            cli.app,
            [
                "watch",
                "--feeds",
                str(feeds_yaml),
                "--sbom",
                str(sbom_path),
                "--format",
                "json",
            ],
        )
        assert res_alias.exit_code == cli.EXIT_OK

    def test_ansi_control_rejection_and_demo_fidelity_regressions(self) -> None:
        from pydantic import ValidationError

        from zerobom.pipeline import run_offline_demo

        # 1) Model boundaries reject ANSI ESC and C1 control characters.
        with pytest.raises(ValidationError, match="control characters"):
            RawArticle(
                url="https://research.example.org/ansi",
                title="Bad\x1b]8;;https://evil.example\x07Title",
                body="Python requests prior to 2.31.0.",
                source_name="Example",
                source_tier=SourceTier.TIER_1,
                published_at=PUBLISHED_AT,
            )

        with pytest.raises(ValidationError, match="control characters"):
            OsvPackage(
                ecosystem="PyPI",
                name="requests\x9b31m",
                purl="pkg:pypi/requests",
            )

        # 2) Rich terminal renderer strips ANSI/OSC-8 escapes from untrusted summaries/quotes.
        outcome_with_esc = PipelineOutcome(
            article=RawArticle(
                url="https://research.example.org/osc8",
                title="Clean Title",
                body="Requests\x1b]8;;https://evil.example\x07 prior to 2.31.0.",
                source_name="Example Research",
                source_tier=SourceTier.TIER_1,
                published_at=PUBLISHED_AT,
            ),
            osv=OsvAdvisory(
                id="PRECVE-2026-OSC80001",
                modified=PUBLISHED_AT,
                published=PUBLISHED_AT,
                summary="Safe summary",
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
            ),
            skipped_reason="Notice:\x1b[31mFAKE\x1b[0m",
        )
        buf = StringIO()
        console = Console(file=buf, no_color=True, width=120)
        render_terminal_outcomes((outcome_with_esc,), console=console)
        rendered = buf.getvalue()
        assert "\x1b" not in rendered
        assert "Notice:FAKE" in rendered

        # 3) Demo carries Debian:11, per-match OpenSSL quote, Example source, and relative assetId.
        demo_out = run_offline_demo()
        assert demo_out.article is not None
        assert demo_out.article.source_name == "Example Security Research"
        assert demo_out.osv is not None
        assert demo_out.osv.id == "PRECVE-2026-7DA3A045"
        by_match = {m.matched_purl: m for m in demo_out.matches}
        assert by_match["pkg:deb/debian/openssl"].ecosystem == "Debian:11"
        assert (
            by_match["pkg:deb/debian/openssl"].evidence_quote
            == "Debian openssl versions before 1.1.1n-0+deb11u5 on Debian 11 systems"
        )
        assert (
            by_match["pkg:pypi/requests"].evidence_quote
            == "Python requests versions prior to 2.31.0 when handling HTTP redirects"
        )
        sarif_log = build_sarif_log((demo_out,))
        for sarif_res in sarif_log["runs"][0]["results"]:
            assert sarif_res["properties"]["assetId"] == "demo_sbom.cdx.json"
        assert (
            sarif_log["runs"][0]["tool"]["driver"]["informationUri"]
            == "https://github.com/zerobom-dev/zerobom"
        )
