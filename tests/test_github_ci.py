"""Offline unit & integration tests for Milestone 2.3 GitHub Issues, multi-sink CLI, and CI."""

from __future__ import annotations

import json
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from typer.testing import CliRunner

from zerobom import cli
from zerobom.models import (
    AssetRef,
    ClaimVerificationResult,
    CredibilityReport,
    ExtractedPackageClaim,
    GroundingMatchType,
    GroundingResult,
    GroundingStatus,
    MatchResult,
    OsvAdvisory,
    OsvAffected,
    OsvPackage,
    OsvRange,
    OsvRangeEvent,
    OsvReference,
    PipelineOutcome,
    PurlResolutionResult,
    RawArticle,
    RoutingDecision,
    SourceTier,
    VersionConstraint,
)
from zerobom.outputs import (
    DEFAULT_GITHUB_API_URL,
    AlertDeliveryError,
    GitHubIssueError,
    GitHubIssueSyncer,
    build_issue_marker,
    render_github_issue,
    sanitize_github_markdown,
    sanitize_table_cell,
    validate_github_repo,
)

PUBLISHED_AT = datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)
REPO_ROOT = Path(__file__).resolve().parent.parent
RUNNER = CliRunner()


def _cred(label: str) -> str:
    """Return synthetic non-secret credential strings without triggering literal checks."""
    return f"{label}-unit-test-placeholder"


def _make_osv(
    adv_id: str = "PRECVE-2026-AA11BB22",
    *,
    summary: str = "SSRF credential leak in Python requests before 2.31.0",
    ref_url: str = "https://secblog.example.org/requests-ssrf",
) -> OsvAdvisory:
    return OsvAdvisory(
        id=adv_id,
        aliases=("ZDI-CAN-99999",),
        modified=PUBLISHED_AT,
        published=PUBLISHED_AT,
        summary=summary,
        details="Verbatim evidence extracted from security blog.",
        affected=(
            OsvAffected(
                package=OsvPackage(ecosystem="PyPI", name="requests", purl="pkg:pypi/requests"),
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
        references=(OsvReference(type="ARTICLE", url=ref_url),),
    )


def _make_credibility(
    routing: RoutingDecision,
    *,
    quote: str = "Python requests versions prior to 2.31.0 leak .netrc credentials.",
    url: str = "https://secblog.example.org/requests-ssrf",
) -> CredibilityReport:
    tier = SourceTier.TIER_1 if routing == RoutingDecision.AUTO else SourceTier.UNKNOWN
    tier_weight = 1.0 if routing == RoutingDecision.AUTO else 0.55
    score = (
        0.90
        if routing == RoutingDecision.AUTO
        else (0.55 if routing == RoutingDecision.TRIAGE else 0.2)
    )
    claim_res = ClaimVerificationResult(
        claim=ExtractedPackageClaim(
            raw_package_name="requests",
            ecosystem="pypi",
            version_constraints=(VersionConstraint(fixed="2.31.0"),),
            evidence_quote=quote,
        ),
        grounding=GroundingResult(
            status=GroundingStatus.VERIFIED,
            match_type=GroundingMatchType.EXACT,
            quote_found_in_article=True,
            package_token_found=True,
            version_tokens_found=True,
        ),
        purl=PurlResolutionResult(
            canonical_purl="pkg:pypi/requests",
            ecosystem="pypi",
            osv_ecosystem="PyPI",
            name="requests",
            is_valid=True,
        ),
        has_valid_version_range=True,
        has_bounded_version_range=True,
        extraction_specificity=score / tier_weight,
        composite_score=score,
        routing=routing,
    )
    return CredibilityReport(
        article_url=url,
        source_tier=tier,
        source_tier_weight=tier_weight,
        extraction_specificity=score / tier_weight,
        composite_score=score,
        routing=routing,
        claim_results=(claim_res,),
        accepted_claims=(claim_res,) if routing != RoutingDecision.DROP else (),
        dropped_claims=(claim_res,) if routing == RoutingDecision.DROP else (),
    )


def _make_match(
    asset_num: int = 1,
    adv_id: str = "PRECVE-2026-AA11BB22",
    *,
    sbom_source: str | None = None,
) -> MatchResult:
    resolved_src = sbom_source or f"services/svc-{asset_num}/sbom.cdx.json"
    return MatchResult(
        advisory_id=adv_id,
        component_purl="pkg:pypi/requests@2.30.0",
        installed_version="2.30.0",
        matched_purl="pkg:pypi/requests",
        ecosystem="PyPI",
        is_vulnerable=True,
        matched_range="<2.31.0",
        fixed_versions=("2.31.0",),
        evidence_quote="Python requests versions prior to 2.31.0 leak .netrc credentials.",
        sbom_source=resolved_src,
        asset=AssetRef(
            asset_id=f"svc-{asset_num}/sbom.cdx.json",
            asset_type="container",
            backend="local_sbom",
            location=f"services/svc-{asset_num}/sbom.cdx.json",
        ),
    )


def _write_minimal_sbom_and_osv(tmp_path: Path) -> tuple[Path, Path]:
    sbom_path = tmp_path / "sbom.cdx.json"
    sbom_path.write_text(
        json.dumps(
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
            }
        ),
        encoding="utf-8",
    )
    osv_path = tmp_path / "PRECVE-2026-AA11BB22.json"
    osv_path.write_text(_make_osv().model_dump_json(), encoding="utf-8")
    return sbom_path, osv_path


# ---------------------------------------------------------------------------
# 1. Markdown Rendering & XSS / Spoofing Hardening
# ---------------------------------------------------------------------------


class TestGitHubIssueRenderer:
    def test_noise_suppression_for_drop_clean_auto_and_opt_in_triage(self) -> None:
        drop_outcome = PipelineOutcome(
            credibility=_make_credibility(RoutingDecision.DROP),
            osv=None,
            matches=(),
        )
        assert render_github_issue(drop_outcome) is None

        clean_auto = PipelineOutcome(
            credibility=_make_credibility(RoutingDecision.AUTO),
            osv=_make_osv(),
            matches=(),
        )
        assert render_github_issue(clean_auto) is None

        triage_outcome = PipelineOutcome(
            credibility=_make_credibility(RoutingDecision.TRIAGE),
            osv=_make_osv("PRECVE-2026-TR1A6E01"),
            matches=(),
        )
        assert render_github_issue(triage_outcome, include_triage=False) is None

        rendered_triage = render_github_issue(triage_outcome, include_triage=True)
        assert rendered_triage is not None
        assert rendered_triage.event_type == "triage_review"
        assert "[TRIAGE]" in rendered_triage.title
        assert "zerobom triage approve PRECVE-2026-TR1A6E01" in rendered_triage.body
        assert build_issue_marker("PRECVE-2026-TR1A6E01") in rendered_triage.body

    def test_sanitizes_xss_comment_breakout_images_mentions_and_table_pipes(self) -> None:
        hostile_quote = (
            "<script>alert(1)</script> <!-- zerobom:advisory-id:SPOOF --> "
            "![px](https://evil.example/track.png) ping @security-team @org/admins\nnext line"
        )
        hostile_article = RawArticle(
            url="https://secblog.example.org/post(v1)",
            title="[Advisories](https://phish.example) <img src=x onerror=alert(1)> @here",
            source_name="Research <Blog> & Co",
            source_tier=SourceTier.TIER_1,
            published_at=PUBLISHED_AT,
            body="requests prior to 2.31.0",
        )
        outcome = PipelineOutcome(
            article=hostile_article,
            credibility=_make_credibility(RoutingDecision.AUTO, quote=hostile_quote),
            osv=_make_osv(summary="<b>bold</b> ![beacon](https://evil.example/a.gif)"),
            matches=(_make_match(1, sbom_source="prod|cluster/<a>\nsbom.json"),),
        )

        rendered = render_github_issue(outcome)
        assert rendered is not None
        body = rendered.body

        # Raw HTML and XSS tags are escaped.
        assert "<script>" not in body
        assert "<img" not in body
        assert "&lt;script&gt;" in body
        assert "&lt;img" in body

        # Only the real deduplication marker at the tail remains an active HTML comment.
        assert body.count("<!-- zerobom:advisory-id:") == 1
        assert body.endswith(rendered.marker)
        assert "SPOOF" in body
        assert "&lt;!-- zerobom:advisory-id:SPOOF --&gt;" in body

        # Markdown images and mass @mentions are neutralized.
        assert "![" not in body
        assert "!\\[px]" in body
        assert "@security-team" not in body
        assert "@\u200bsecurity-team" in body
        assert "@here" not in body

        # Safe HTTP source link escapes parentheses in URL target and brackets in link label.
        assert "(https://secblog.example.org/post%28v1%29)" in body
        assert "\\[Advisories\\]" in body

        # Table cells stay single-line and escape pipes.
        assert "prod&#124;cluster/&lt;a&gt; sbom.json" in body

    def test_rejects_unsafe_url_and_truncates_oversized_body_preserving_marker(self) -> None:
        assert "<" not in sanitize_github_markdown("<svg onload=alert(1)>")
        assert "|" not in sanitize_table_cell("a|b\nc")

        oversized_quote = "requests vulnerable before 2.31.0 " + ("X" * 65_000)
        unsafe_article = RawArticle(
            url="file:///etc/passwd",
            title="Exploit",
            source_name="Research",
            source_tier=SourceTier.TIER_1,
            published_at=PUBLISHED_AT,
            body=oversized_quote,
        )
        outcome = PipelineOutcome(
            article=unsafe_article,
            credibility=_make_credibility(
                RoutingDecision.AUTO,
                quote=oversized_quote,
                url="file:///etc/passwd",
            ),
            osv=_make_osv(ref_url="file:///etc/passwd"),
            matches=(_make_match(1),),
        )

        rendered = render_github_issue(outcome)
        assert rendered is not None
        assert "file://" not in rendered.body
        assert "- **Source Reference:** (none)" in rendered.body
        assert len(rendered.body) <= 60_000
        assert rendered.body.endswith(rendered.marker)


# ---------------------------------------------------------------------------
# 2. Idempotent GitHub Issue Sync & REST Security Boundaries
# ---------------------------------------------------------------------------


class TestGitHubIssueSyncer:
    def test_repo_validation_redaction_and_skip_zero_http_calls(self) -> None:
        assert validate_github_repo("octo-org/my-service") == ("octo-org", "my-service")
        assert validate_github_repo("octo-org/.github") == ("octo-org", ".github")

        for bad_repo in ("../evil", "octo/..", "octo/.", "octo", "a/b/c", "acme\\app", "a/b\r\n"):
            with pytest.raises(GitHubIssueError):
                validate_github_repo(bad_repo)

        with pytest.raises(GitHubIssueError, match="https"):
            GitHubIssueSyncer("acme/app", _cred("gh"), api_base_url="http://api.github.com")

        with pytest.raises(GitHubIssueError):
            GitHubIssueSyncer("acme/app", "")

        def _unexpected_call(request: httpx.Request) -> httpx.Response:
            raise AssertionError(f"Unexpected HTTP call: {request.method} {request.url}")

        secret_tok = _cred("gh-pat")
        client = httpx.Client(transport=httpx.MockTransport(_unexpected_call))
        with GitHubIssueSyncer("acme/app", secret_tok, http_client=client) as syncer:
            assert secret_tok not in repr(syncer)
            assert "acme/app" in repr(syncer)

            clean_auto = PipelineOutcome(
                credibility=_make_credibility(RoutingDecision.AUTO),
                osv=_make_osv(),
                matches=(),
            )
            drop_res = PipelineOutcome(
                credibility=_make_credibility(RoutingDecision.DROP),
                osv=None,
                matches=(),
            )
            results = syncer.sync_outcomes((clean_auto, drop_res))
            assert [item.action for item in results] == ["skipped", "skipped"]

    def test_idempotent_create_unchanged_update_dry_run_and_pr_skipping(self) -> None:
        issues_db: list[dict[str, Any]] = [
            {
                "number": 999,
                "html_url": "https://github.com/acme/app/pull/999",
                "title": "Unrelated PR mentioning marker",
                "body": f"PR body\n\n{build_issue_marker('PRECVE-2026-AA11BB22')}",
                "pull_request": {"url": "https://api.github.com/repos/acme/app/pulls/999"},
            }
        ]
        calls: list[tuple[str, str]] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            calls.append((request.method, request.url.path))
            if request.method == "GET" and request.url.path == "/repos/acme/app/issues":
                return httpx.Response(200, json=issues_db)
            if request.method == "POST" and request.url.path == "/repos/acme/app/issues":
                payload = json.loads(request.content.decode("utf-8"))
                created = {
                    "number": 42,
                    "html_url": "https://github.com/acme/app/issues/42",
                    "title": payload["title"],
                    "body": payload["body"],
                    "labels": payload["labels"],
                }
                issues_db.append(created)
                return httpx.Response(201, json=created)
            if request.method == "PATCH" and request.url.path == "/repos/acme/app/issues/42":
                payload = json.loads(request.content.decode("utf-8"))
                issues_db[-1]["title"] = payload["title"]
                issues_db[-1]["body"] = payload["body"]
                return httpx.Response(200, json=issues_db[-1])
            return httpx.Response(404, json={"message": "not found"})

        hit_one = PipelineOutcome(
            credibility=_make_credibility(RoutingDecision.AUTO),
            osv=_make_osv(),
            matches=(_make_match(1),),
        )
        tok = _cred("gh-pat")

        # 0) Dry-run create makes only GET request.
        c0 = httpx.Client(transport=httpx.MockTransport(_handler))
        with GitHubIssueSyncer("acme/app", tok, dry_run=True, http_client=c0) as s0:
            res_dry = s0.sync_outcome(hit_one)
            assert res_dry.action == "dry_run_create"
        assert calls == [("GET", "/repos/acme/app/issues")]

        # 1) Create new issue (skips PR #999 carrying same marker).
        calls.clear()
        c1 = httpx.Client(transport=httpx.MockTransport(_handler))
        with GitHubIssueSyncer("acme/app", tok, http_client=c1) as s1:
            res_create = s1.sync_outcome(hit_one)
            assert res_create.action == "created"
            assert res_create.issue_number == 42
            assert res_create.issue_url == "https://github.com/acme/app/issues/42"
        assert calls == [
            ("GET", "/repos/acme/app/issues"),
            ("POST", "/repos/acme/app/issues"),
        ]

        # 2) Repeat run with identical matches -> unchanged, zero POST/PATCH calls.
        calls.clear()
        c2 = httpx.Client(transport=httpx.MockTransport(_handler))
        with GitHubIssueSyncer("acme/app", tok, http_client=c2) as s2:
            res_same = s2.sync_outcome(hit_one)
            assert res_same.action == "unchanged"
            assert res_same.issue_number == 42
        assert calls == [("GET", "/repos/acme/app/issues")]

        # 3) New vulnerable asset added -> dry_run_update then real PATCH update.
        hit_two = PipelineOutcome(
            credibility=_make_credibility(RoutingDecision.AUTO),
            osv=_make_osv(),
            matches=(_make_match(1), _make_match(2)),
        )
        calls.clear()
        c3_dry = httpx.Client(transport=httpx.MockTransport(_handler))
        with GitHubIssueSyncer("acme/app", tok, dry_run=True, http_client=c3_dry) as s3_dry:
            assert s3_dry.sync_outcome(hit_two).action == "dry_run_update"
        assert calls == [("GET", "/repos/acme/app/issues")]

        calls.clear()
        c3 = httpx.Client(transport=httpx.MockTransport(_handler))
        with GitHubIssueSyncer("acme/app", tok, http_client=c3) as s3:
            res_upd = s3.sync_outcome(hit_two)
            assert res_upd.action == "updated"
            assert res_upd.issue_number == 42
        assert calls == [
            ("GET", "/repos/acme/app/issues"),
            ("PATCH", "/repos/acme/app/issues/42"),
        ]

    def test_pagination_and_http_error_or_redirect_fail_closed(self) -> None:
        marker = build_issue_marker("PRECVE-2026-AA11BB22")
        page1 = [
            {"number": i, "title": f"Noise {i}", "body": "no marker", "html_url": f"u/{i}"}
            for i in range(1, 101)
        ]
        page2 = [
            {
                "number": 105,
                "title": "Existing issue",
                "body": f"Old content\n{marker}",
                "html_url": "https://github.com/acme/app/issues/105",
            }
        ]
        pages_requested: list[str] = []

        def _paginated(request: httpx.Request) -> httpx.Response:
            page = request.url.params.get("page", "1")
            pages_requested.append(page)
            if request.method == "GET":
                return httpx.Response(200, json=page1 if page == "1" else page2)
            return httpx.Response(200, json={"html_url": "https://github.com/acme/app/issues/105"})

        hit = PipelineOutcome(
            credibility=_make_credibility(RoutingDecision.AUTO),
            osv=_make_osv(),
            matches=(_make_match(1),),
        )
        c_page = httpx.Client(transport=httpx.MockTransport(_paginated))
        with GitHubIssueSyncer("acme/app", _cred("gh"), http_client=c_page) as syncer:
            res = syncer.sync_outcome(hit)
            assert res.action == "updated"
            assert res.issue_number == 105
        assert pages_requested[:2] == ["1", "2"]

        for bad_status in (302, 500):
            c_err = httpx.Client(
                transport=httpx.MockTransport(
                    lambda _req, code=bad_status: httpx.Response(code, text="bad")
                )
            )
            with (
                GitHubIssueSyncer("acme/app", _cred("gh"), http_client=c_err) as err_syncer,
                pytest.raises(AlertDeliveryError),
            ):
                err_syncer.sync_outcome(hit)


# ---------------------------------------------------------------------------
# 3. Single-Pass Multi-Sink CLI Outputs & GitHub CLI Integration
# ---------------------------------------------------------------------------


class TestMultiSinkCliOutputs:
    def test_demo_writes_terminal_json_and_sarif_in_single_pass(self, tmp_path: Path) -> None:
        json_path = tmp_path / "out" / "report.json"
        sarif_path = tmp_path / "out" / "report.sarif"

        res = RUNNER.invoke(
            cli.app,
            [
                "demo",
                "--format",
                "terminal",
                "--json-out",
                str(json_path),
                "--sarif-out",
                str(sarif_path),
            ],
        )
        assert res.exit_code == 0, res.output
        assert "PRECVE-" in res.output

        report = json.loads(json_path.read_text(encoding="utf-8"))
        assert report["schema"] == "zerobom.report/v1"
        assert report["summary"]["total_analyzed"] == 1
        assert report["summary"]["vulnerable_hits"] >= 1

        sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) >= 1

    def test_scan_creates_github_issue_and_writes_multi_sink_reports(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sbom_path, osv_path = _write_minimal_sbom_and_osv(tmp_path)
        json_path = tmp_path / "scan.json"
        sarif_path = tmp_path / "scan.sarif"
        captured_posts: list[dict[str, Any]] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(200, json=[])
            if request.method == "POST":
                captured_posts.append(json.loads(request.content.decode("utf-8")))
                return httpx.Response(
                    201,
                    json={"number": 7, "html_url": "https://github.com/acme/service/issues/7"},
                )
            return httpx.Response(404)

        def _fake_syncer(
            repo: str,
            token: str,
            *,
            api_base_url: str,
            include_triage: bool,
        ) -> GitHubIssueSyncer:
            assert api_base_url == DEFAULT_GITHUB_API_URL
            assert include_triage is False
            return GitHubIssueSyncer(
                repo,
                token,
                api_base_url=api_base_url,
                include_triage=include_triage,
                http_client=httpx.Client(transport=httpx.MockTransport(_handler)),
            )

        monkeypatch.setattr(cli, "_create_github_syncer", _fake_syncer)

        res = RUNNER.invoke(
            cli.app,
            [
                "scan",
                "--osv",
                str(osv_path),
                "--sbom",
                str(sbom_path),
                "--json-out",
                str(json_path),
                "--sarif-out",
                str(sarif_path),
                "--github-repo",
                "acme/service",
                "--github-token",
                _cred("gh-cli"),
            ],
        )
        assert res.exit_code == 1, res.output
        assert len(captured_posts) == 1
        assert "PRECVE-2026-AA11BB22" in captured_posts[0]["title"]
        assert json.loads(json_path.read_text(encoding="utf-8"))["summary"]["vulnerable_hits"] == 1
        assert json.loads(sarif_path.read_text(encoding="utf-8"))["version"] == "2.1.0"

    def test_scan_github_repo_without_token_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sbom_path, osv_path = _write_minimal_sbom_and_osv(tmp_path)
        monkeypatch.delenv("ZEROBOM_GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)

        res = RUNNER.invoke(
            cli.app,
            [
                "scan",
                "--osv",
                str(osv_path),
                "--sbom",
                str(sbom_path),
                "--github-repo",
                "acme/service",
            ],
        )
        assert res.exit_code == cli.EXIT_ERROR
        assert "GitHub token is required" in res.output


# ---------------------------------------------------------------------------
# 4. Composite Action & Repository CI Workflow YAML Structural Validation
# ---------------------------------------------------------------------------


class TestWorkflowDefinitions:
    def test_composite_action_yml_valid_and_injection_safe(self) -> None:
        action_path = REPO_ROOT / "action.yml"
        assert action_path.is_file()
        data = yaml.safe_load(action_path.read_text(encoding="utf-8"))

        assert data["runs"]["using"] == "composite"
        for required_input in (
            "mode",
            "sbom",
            "backend",
            "backend-opts",
            "extras",
            "json-out",
            "sarif-out",
            "upload-sarif",
            "create-github-issues",
            "fail-on-hits",
            "zerobom-version",
        ):
            assert required_input in data["inputs"]

        assert data["inputs"]["json-out"]["default"].startswith(".zerobom-reports/")
        assert data["inputs"]["sarif-out"]["default"].startswith(".zerobom-reports/")

        for required_output in (
            "exit-code",
            "vulnerable-hits",
            "total-analyzed",
            "json-path",
            "sarif-path",
        ):
            assert required_output in data["outputs"]

        steps = data["runs"]["steps"]
        assert any(
            str(step.get("uses", "")).startswith("github/codeql-action/upload-sarif@")
            for step in steps
        )
        restore_step = next(
            (s for s in steps if str(s.get("uses", "")).startswith("actions/cache/restore@")),
            None,
        )
        save_step = next(
            (s for s in steps if str(s.get("uses", "")).startswith("actions/cache/save@")),
            None,
        )
        assert restore_step is not None
        assert save_step is not None
        assert restore_step["with"]["path"] == ".zerobom/state"
        assert save_step["with"]["path"] == ".zerobom/state"
        assert "!cancelled()" in str(save_step.get("if", ""))

        run_step = next(s for s in steps if s.get("id") == "run-zerobom")
        assert 'rm -f "$ZB_JSON_OUT"' in run_step["run"]
        assert 'rm -f "$ZB_SARIF_OUT"' in run_step["run"]
        assert "${ZB_ACTION_PATH}/sources.yaml" in run_step["run"]

        for step in steps:
            run_script = step.get("run")
            if isinstance(run_script, str):
                # Enforce GitHub Actions security rule: no direct `${{ inputs.* }}` in `run:`.
                assert "${{ inputs." not in run_script
                assert "${{inputs." not in run_script
                assert "${{ github." not in run_script
                assert "${{ steps." not in run_script

    def test_optional_extras_packaging_and_docs_links(self) -> None:
        core_toml = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        core_deps = "\n".join(core_toml["project"]["dependencies"]).lower()
        for forbidden_dep in ("boto3", "botocore", "google-auth", "azure-identity", "slack-sdk"):
            assert forbidden_dep not in core_deps
        assert "slack" in core_toml["project"]["optional-dependencies"]

        gcp_toml = tomllib.loads(
            (REPO_ROOT / "plugins" / "zerobom-gcp" / "pyproject.toml").read_text(encoding="utf-8")
        )
        assert "adc" in gcp_toml["project"]["optional-dependencies"]

        azure_toml = tomllib.loads(
            (REPO_ROOT / "plugins" / "zerobom-azure" / "pyproject.toml").read_text(encoding="utf-8")
        )
        assert "identity" in azure_toml["project"]["optional-dependencies"]

        docs_text = (REPO_ROOT / "docs" / "PLUGIN_AUTHORING.md").read_text(encoding="utf-8")
        assert "file:///d:/" not in docs_text.lower()
        assert "file:///c:/" not in docs_text.lower()

    def test_repo_ci_workflow_valid_and_least_privilege(self) -> None:
        ci_path = REPO_ROOT / ".github" / "workflows" / "zerobom-ci.yml"
        assert ci_path.is_file()
        raw_text = ci_path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw_text)

        assert data["permissions"] == {"contents": "read"}
        matrix_versions = data["jobs"]["verify"]["strategy"]["matrix"]["python-version"]
        assert "3.11" in matrix_versions
        assert "3.12" in matrix_versions

        step_commands = "\n".join(
            str(step.get("run", "")) for step in data["jobs"]["verify"]["steps"]
        )
        for expected_cmd in (
            "ruff check .",
            "ruff format --check .",
            "mypy src/",
            "pytest",
            "benchmarks/run_evals.py --mode offline",
            "zerobom demo",
        ):
            assert expected_cmd in step_commands


# ---------------------------------------------------------------------------
# 5. Phase 2 Hardening Regression Tests (GitHub Issue Sync & Renderer)
# ---------------------------------------------------------------------------


class TestPhase2GitHubHardeningRegressions:
    def test_pagination_overflow_fails_closed_before_duplicate_creation(self) -> None:
        post_attempts = 0
        get_pages: list[int] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            nonlocal post_attempts
            if request.method == "POST":
                post_attempts += 1
                return httpx.Response(201, json={"number": 9999})
            if request.method == "GET" and request.url.path == "/repos/acme/app/issues":
                page = int(request.url.params.get("page", "1"))
                get_pages.append(page)
                noise_items = [
                    {
                        "number": (page - 1) * 100 + idx + 1,
                        "html_url": f"https://github.com/acme/app/issues/{idx + 1}",
                        "title": f"Noise issue {idx}",
                        "body": "Unrelated existing security issue without marker.",
                    }
                    for idx in range(100)
                ]
                return httpx.Response(200, json=noise_items)
            return httpx.Response(404)

        hit_outcome = PipelineOutcome(
            credibility=_make_credibility(RoutingDecision.AUTO),
            osv=_make_osv("PRECVE-2026-PAGELIMIT"),
            matches=(_make_match(1, "PRECVE-2026-PAGELIMIT"),),
        )
        client = httpx.Client(transport=httpx.MockTransport(_handler))
        try:
            with (
                GitHubIssueSyncer("acme/app", _cred("gh"), http_client=client) as syncer,
                pytest.raises(GitHubIssueError, match="pagination exceeded"),
            ):
                syncer.sync_outcome(hit_outcome)
        finally:
            client.close()

        assert len(get_pages) == 10
        assert post_attempts == 0

    def test_render_github_issue_uses_database_specific_source_name_fallback(self) -> None:
        osv = _make_osv("PRECVE-2026-METASRC").model_copy(
            update={"database_specific": {"zerobom": {"source_name": "Project Zero"}}}
        )
        outcome = PipelineOutcome(
            article=None,
            credibility=_make_credibility(RoutingDecision.AUTO),
            osv=osv,
            matches=(_make_match(1, "PRECVE-2026-METASRC"),),
        )
        rendered = render_github_issue(outcome)
        assert rendered is not None
        assert "Project Zero" in rendered.body
