"""Comprehensive offline unit & integration tests for Milestone 2.2 alerting & triage."""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import socket
import threading
import types
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
import pytest
from typer.testing import CliRunner

from zerobom import cli
from zerobom.backends import BackendError, LocalSbomBackend
from zerobom.ingest import SafeHttpFetcher
from zerobom.models import (
    AssetRef,
    ClaimVerificationResult,
    CredibilityReport,
    ExtractedAdvisory,
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
    AlertDeliveryError,
    SlackNotifier,
    WebhookNotifier,
    build_slack_auto_payload,
    build_slack_triage_payload,
    escape_slack_mrkdwn,
    sign_webhook_body,
)
from zerobom.triage import (
    MAX_SLACK_CALLBACK_BYTES,
    TriageActionHandler,
    TriageError,
    TriageQueueStore,
    TriageStatus,
    TriageWebhookServer,
    post_slack_response_url,
    run_socket_mode_worker,
    validate_triage_id,
    verify_slack_signature,
)

PUBLISHED_AT = datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)
RUNNER = CliRunner()


def _cred(label: str) -> str:
    """Return synthetic non-secret signing/webhook test strings cleanly."""
    return f"{label}-unit-test-placeholder"


def _public_dns(_host: str, _port: int) -> tuple[str, ...]:
    return ("93.184.216.34",)


def _private_dns(_host: str, _port: int) -> tuple[str, ...]:
    return ("10.0.0.5",)


def _make_osv(adv_id: str = "PRECVE-2026-AA11BB22") -> OsvAdvisory:
    return OsvAdvisory(
        id=adv_id,
        modified=PUBLISHED_AT,
        published=PUBLISHED_AT,
        summary="SSRF credential leak in Python requests before 2.31.0",
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
        references=(OsvReference(type="ARTICLE", url="https://secblog.example.org/requests-ssrf"),),
    )


def _make_credibility(
    routing: RoutingDecision,
    *,
    quote: str = "Python requests versions prior to 2.31.0 leak .netrc credentials.",
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
        article_url="https://secblog.example.org/requests-ssrf",
        source_tier=tier,
        source_tier_weight=tier_weight,
        extraction_specificity=score / tier_weight,
        composite_score=score,
        routing=routing,
        claim_results=(claim_res,),
        accepted_claims=(claim_res,) if routing != RoutingDecision.DROP else (),
        dropped_claims=(claim_res,) if routing == RoutingDecision.DROP else (),
    )


def _make_match(asset_num: int = 1, adv_id: str = "PRECVE-2026-AA11BB22") -> MatchResult:
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
        sbom_source=f"services/svc-{asset_num}/sbom.cdx.json",
        asset=AssetRef(
            asset_id=f"svc-{asset_num}/sbom.cdx.json",
            asset_type="container",
            backend="local_sbom",
            location=f"services/svc-{asset_num}/sbom.cdx.json",
        ),
    )


def _write_sample_sbom(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
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
    return path


def _sign_slack_request(body: bytes, secret: str, ts: int) -> dict[str, str]:
    sig = hmac.new(
        secret.encode("utf-8"),
        f"v0:{ts}:".encode("ascii") + body,
        hashlib.sha256,
    ).hexdigest()
    return {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Slack-Request-Timestamp": str(ts),
        "X-Slack-Signature": f"v0={sig}",
    }


# ---------------------------------------------------------------------------
# 1. Generic Webhook Alerting & SSRF Defenses
# ---------------------------------------------------------------------------


class TestWebhookAlerting:
    def test_auto_triage_drop_policy_and_hmac_signing(self) -> None:
        captured: list[tuple[dict[str, str], bytes]] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            captured.append((dict(request.headers), request.content))
            return httpx.Response(202, json={"accepted": True})

        signing_val = _cred("hmac-key")
        client = httpx.Client(transport=httpx.MockTransport(_handler))
        notifier = WebhookNotifier(
            "https://alerts.example.org/hooks/secret-token-path",
            signing_secret=signing_val,
            dns_resolver=_public_dns,
            http_client=client,
        )
        try:
            assert signing_val not in repr(notifier)
            assert "secret-token-path" not in repr(notifier)
            assert "https://alerts.example.org/..." in repr(notifier)

            # 1) AUTO with 0 hits -> silent skip (0 HTTP calls).
            auto_clean = PipelineOutcome(
                credibility=_make_credibility(RoutingDecision.AUTO),
                osv=_make_osv("PRECVE-2026-00000001"),
                matches=(),
            )
            res_skip_auto = notifier.send_outcome(auto_clean)
            assert res_skip_auto.event_type == "skipped"
            assert res_skip_auto.delivered is False

            # 2) DROP -> silent skip (0 HTTP calls).
            drop_outcome = PipelineOutcome(
                credibility=_make_credibility(RoutingDecision.DROP),
                osv=None,
                matches=(),
            )
            res_drop = notifier.send_outcome(drop_outcome)
            assert res_drop.delivered is False
            assert len(captured) == 0

            # 3) AUTO with hits > 0 -> signed consolidated POST.
            auto_hit = PipelineOutcome(
                credibility=_make_credibility(RoutingDecision.AUTO),
                osv=_make_osv("PRECVE-2026-AA11BB22"),
                matches=(_make_match(1), _make_match(2)),
            )
            res_auto = notifier.send_outcome(auto_hit)
            assert res_auto.delivered is True
            assert res_auto.event_type == "auto_hit"
            assert res_auto.status_code == 202
            assert len(captured) == 1

            hdrs, raw_body = captured[0]
            ts = int(hdrs["x-zerobom-timestamp"])
            assert hmac.compare_digest(
                hdrs["x-zerobom-signature"],
                sign_webhook_body(raw_body, signing_val, ts),
            )
            parsed_body = json.loads(raw_body.decode("utf-8"))
            assert parsed_body["advisory_id"] == "PRECVE-2026-AA11BB22"
            assert len(parsed_body["vulnerable_matches"]) == 2

            # 4) TRIAGE -> sends review notification with quote & approve CLI command.
            triage_outcome = PipelineOutcome(
                credibility=_make_credibility(RoutingDecision.TRIAGE),
                osv=_make_osv("PRECVE-2026-TRIAGE01"),
                matches=(),
            )
            res_triage = notifier.send_outcome(triage_outcome, triage_id="PRECVE-2026-TRIAGE01")
            assert res_triage.delivered is True
            assert res_triage.event_type == "triage_review"
            assert len(captured) == 2
            triage_json = json.loads(captured[1][1].decode("utf-8"))
            assert (
                triage_json["triage"]["approve_command"]
                == "zerobom triage approve PRECVE-2026-TRIAGE01"
            )
            assert triage_json["evidence_quotes"]
        finally:
            notifier.close()
            client.close()

    def test_webhook_ssrf_and_redirect_rejection(self) -> None:
        with pytest.raises(AlertDeliveryError, match="https://"):
            WebhookNotifier("http://alerts.example.org/hook", dns_resolver=_public_dns)
        with pytest.raises(AlertDeliveryError, match="non-public"):
            WebhookNotifier(
                "https://127.0.0.1/hook",
                dns_resolver=_public_dns,
            )
        with pytest.raises(AlertDeliveryError, match="SSRF"):
            WebhookNotifier("https://internal.corp/hook", dns_resolver=_private_dns)
        with pytest.raises(AlertDeliveryError, match="credentials"):
            WebhookNotifier("https://user:pass@alerts.example.org/hook", dns_resolver=_public_dns)

        # allow_private_targets=True permits internal webhook explicitly.
        priv = WebhookNotifier(
            "https://internal.corp/hook",
            allow_private_targets=True,
            dns_resolver=_private_dns,
        )
        priv.close()

        # 302 redirect from webhook endpoint fails closed.
        redir_client = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: httpx.Response(302, headers={"Location": "http://169.254.169.254"})
            )
        )
        redir_notifier = WebhookNotifier(
            "https://alerts.example.org/hook",
            dns_resolver=_public_dns,
            http_client=redir_client,
        )
        try:
            hit = PipelineOutcome(
                credibility=_make_credibility(RoutingDecision.AUTO),
                osv=_make_osv(),
                matches=(_make_match(1),),
            )
            with pytest.raises(AlertDeliveryError, match="redirect"):
                redir_notifier.send_outcome(hit)
        finally:
            redir_client.close()


# ---------------------------------------------------------------------------
# 2. Slack Block Kit Formatter & Host-Pinned Notifier
# ---------------------------------------------------------------------------


class TestSlackAlerting:
    def test_escape_slack_mrkdwn_blocks_mentions_links_and_controls(self) -> None:
        hostile = "Alert <!channel> and <!here> via <@U12345> <https://evil.test|click me> & \x00\r"
        escaped = escape_slack_mrkdwn(hostile)
        assert "<!channel>" not in escaped
        assert "&lt;!channel&gt;" in escaped
        assert "&lt;!here&gt;" in escaped
        assert "&lt;@U12345&gt;" in escaped
        assert "&lt;https://evil.test|click me&gt;" in escaped
        assert "&amp;" in escaped
        assert "\x00" not in escaped
        assert "\r" not in escaped

    def test_slack_notifier_host_pinning_block_kit_overflow_and_buttons(self) -> None:
        with pytest.raises(AlertDeliveryError, match="allowlist"):
            SlackNotifier("https://evil.example/services/T/B/S", dns_resolver=_public_dns)

        many_matches = tuple(_make_match(i) for i in range(1, 13))
        auto_payload = build_slack_auto_payload(
            PipelineOutcome(
                credibility=_make_credibility(
                    RoutingDecision.AUTO,
                    quote="<!everyone> Requests < 2.31.0 vulnerable",
                ),
                osv=_make_osv(),
                matches=many_matches,
            )
        )
        rendered_text = json.dumps(auto_payload)
        assert "<!everyone>" not in rendered_text
        assert "&lt;!everyone&gt;" in rendered_text
        assert "and 2 more vulnerable asset hit(s)" in rendered_text

        triage_outcome = PipelineOutcome(
            credibility=_make_credibility(RoutingDecision.TRIAGE),
            osv=_make_osv("PRECVE-2026-SLK12345"),
            matches=(),
        )
        triage_payload = build_slack_triage_payload(
            triage_outcome,
            triage_id="PRECVE-2026-SLK12345",
        )
        actions_blocks = [b for b in triage_payload["blocks"] if b["type"] == "actions"]
        assert len(actions_blocks) == 1
        action_ids = [el["action_id"] for el in actions_blocks[0]["elements"]]
        assert action_ids == ["zerobom_triage_approve", "zerobom_triage_reject"]

        sent_payloads: list[dict[str, Any]] = []
        client = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: (
                    sent_payloads.append(json.loads(req.content.decode("utf-8"))),
                    httpx.Response(200, text="ok"),
                )[1]
            )
        )
        slack = SlackNotifier(
            "https://hooks.slack.com/services/T00/B00/SECRET_HOOK_TOKEN",
            dns_resolver=_public_dns,
            http_client=client,
        )
        try:
            assert "SECRET_HOOK_TOKEN" not in repr(slack)
            assert "https://hooks.slack.com/..." in repr(slack)
            res = slack.send_outcome(triage_outcome, triage_id="PRECVE-2026-SLK12345")
            assert res.delivered is True
            assert len(sent_payloads) == 1
        finally:
            client.close()


# ---------------------------------------------------------------------------
# 3. Triage Queue Store & Shared Action Handler
# ---------------------------------------------------------------------------


class TestTriageQueueAndActions:
    def test_sqlite_queue_dedup_approve_reject_and_idempotency(self, tmp_path: Path) -> None:
        sbom_path = _write_sample_sbom(tmp_path / "sbom.cdx.json")
        db_path = tmp_path / "triage.sqlite"
        store = TriageQueueStore(db_path)

        with pytest.raises(TriageError, match="Invalid triage ID"):
            validate_triage_id("../bad; DROP TABLE triage_items;")

        # AUTO/DROP are not enqueued.
        assert (
            store.enqueue_outcome(
                PipelineOutcome(
                    credibility=_make_credibility(RoutingDecision.AUTO),
                    osv=_make_osv(),
                )
            )
            is None
        )

        triage_outcome = PipelineOutcome(
            article=RawArticle(
                url="https://secblog.example.org/requests-ssrf",
                title="Requests netrc SSRF writeup",
                body="Python requests versions prior to 2.31.0 leak .netrc credentials.",
                source_name="Sec Research Blog",
                source_tier=SourceTier.UNKNOWN,
                published_at=PUBLISHED_AT,
            ),
            credibility=_make_credibility(RoutingDecision.TRIAGE),
            osv=_make_osv("PRECVE-2026-QUEUE001"),
        )
        rec = store.enqueue_outcome(triage_outcome)
        assert rec is not None
        assert rec.status == TriageStatus.PENDING
        assert len(store.list_items(status=TriageStatus.PENDING)) == 1

        # Independent channel notification deduplication.
        assert store.should_notify(rec.triage_id, "digest-wh", channel="webhook") is True
        store.mark_notified(rec.triage_id, "digest-wh", channel="webhook")
        assert store.should_notify(rec.triage_id, "digest-wh", channel="webhook") is False
        assert store.should_notify(rec.triage_id, "digest-slack", channel="slack") is True

        # Approve triggers deterministic SBOM scan & consolidated webhook alert.
        webhook_calls: list[bytes] = []
        wh_client = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: (webhook_calls.append(req.content), httpx.Response(200))[1]
            )
        )
        wh = WebhookNotifier(
            "https://alerts.example.org/triage-hit",
            dns_resolver=_public_dns,
            http_client=wh_client,
        )
        try:
            handler = TriageActionHandler(
                store,
                backend_factory=lambda: LocalSbomBackend(sbom_path),
                alert_notifiers=(wh,),
            )
            res1 = handler.approve("PRECVE-2026-QUEUE001", actor="alice", note="Confirmed")
            assert res1.already_decided is False
            assert res1.alert_sent is True
            assert len(res1.matches) == 1
            assert res1.record.status == TriageStatus.APPROVED
            assert res1.record.last_match_count == 1
            assert len(webhook_calls) == 1

            # Second approve is strictly idempotent: no duplicate scan or alert!
            res2 = handler.approve("PRECVE-2026-QUEUE001", actor="bob")
            assert res2.already_decided is True
            assert res2.alert_sent is False
            assert len(webhook_calls) == 1

            # Re-enqueuing an already-decided item does not revert status to PENDING.
            requeued = store.enqueue_outcome(triage_outcome)
            assert requeued is not None
            assert requeued.status == TriageStatus.APPROVED
        finally:
            wh_client.close()

        # Reject flow on a second pending advisory.
        rec2 = store.enqueue_outcome(
            PipelineOutcome(
                credibility=_make_credibility(RoutingDecision.TRIAGE),
                osv=_make_osv("PRECVE-2026-QUEUE002"),
            )
        )
        assert rec2 is not None
        rej_res = TriageActionHandler(store).reject(
            "PRECVE-2026-QUEUE002",
            actor="alice",
            note="Not used in prod",
        )
        assert rej_res.already_decided is False
        assert rej_res.record.status == TriageStatus.REJECTED
        assert (
            TriageActionHandler(store).reject("PRECVE-2026-QUEUE002", actor="bob").already_decided
        )


# ---------------------------------------------------------------------------
# 4. Signed Slack HTTP Callback Worker & Socket Mode Adapter
# ---------------------------------------------------------------------------


class TestSignedSlackWorkerAndSocketMode:
    def test_verify_slack_signature_and_replay_window(self) -> None:
        secret = _cred("slack-signing")
        body = b"payload=%7B%22type%22%3A%22block_actions%22%7D"
        now_ts = 1_780_000_000
        headers = _sign_slack_request(body, secret, now_ts)

        assert (
            verify_slack_signature(
                body,
                timestamp_header=headers["X-Slack-Request-Timestamp"],
                signature_header=headers["X-Slack-Signature"],
                signing_secret=secret,
                now=now_ts,
            )
            is True
        )
        assert (
            verify_slack_signature(
                body + b"tamper",
                timestamp_header=headers["X-Slack-Request-Timestamp"],
                signature_header=headers["X-Slack-Signature"],
                signing_secret=secret,
                now=now_ts,
            )
            is False
        )
        assert (
            verify_slack_signature(
                body,
                timestamp_header=headers["X-Slack-Request-Timestamp"],
                signature_header=headers["X-Slack-Signature"],
                signing_secret=_cred("wrong"),
                now=now_ts,
            )
            is False
        )
        # Reject stale (>300s old) and far-future (>300s ahead) timestamps.
        assert (
            verify_slack_signature(
                body,
                timestamp_header=headers["X-Slack-Request-Timestamp"],
                signature_header=headers["X-Slack-Signature"],
                signing_secret=secret,
                now=now_ts + 301,
            )
            is False
        )
        assert (
            verify_slack_signature(
                body,
                timestamp_header=headers["X-Slack-Request-Timestamp"],
                signature_header=headers["X-Slack-Signature"],
                signing_secret=secret,
                now=now_ts - 301,
            )
            is False
        )

    def test_live_http_worker_end_to_end_signed_approve_and_guards(self, tmp_path: Path) -> None:
        sbom_path = _write_sample_sbom(tmp_path / "sbom.cdx.json")
        store = TriageQueueStore(tmp_path / "worker.sqlite")
        store.enqueue_outcome(
            PipelineOutcome(
                credibility=_make_credibility(RoutingDecision.TRIAGE),
                osv=_make_osv("PRECVE-2026-WRK11111"),
            )
        )

        slack_updates: list[dict[str, Any]] = []
        resp_client = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: (
                    slack_updates.append(json.loads(req.content.decode("utf-8"))),
                    httpx.Response(200, json={"ok": True}),
                )[1]
            )
        )

        secret = _cred("worker-signing")
        fixed_now = 1_780_000_000
        handler = TriageActionHandler(
            store,
            backend_factory=lambda: LocalSbomBackend(sbom_path),
        )
        server = TriageWebhookServer(
            handler,
            signing_secret=secret,
            host="127.0.0.1",
            port=0,
            dns_resolver=_public_dns,
            response_http_client=resp_client,
            now_fn=lambda: fixed_now,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_port}"

        try:
            with httpx.Client(timeout=5.0) as client:
                health = client.get(f"{base_url}/healthz")
                assert health.status_code == 200
                assert health.json() == {"status": "ok"}

                # Reject invalid signature (401).
                bad_body = urlencode({"payload": json.dumps({"type": "block_actions"})}).encode(
                    "utf-8"
                )
                unauth = client.post(
                    f"{base_url}/slack/actions",
                    content=bad_body,
                    headers={
                        "X-Slack-Request-Timestamp": str(fixed_now),
                        "X-Slack-Signature": "v0=" + ("0" * 64),
                    },
                )
                assert unauth.status_code == 401

                # Reject oversized payload (413).
                huge_body = b"x" * (MAX_SLACK_CALLBACK_BYTES + 1)
                too_big = client.post(
                    f"{base_url}/slack/actions",
                    content=huge_body,
                    headers=_sign_slack_request(huge_body, secret, fixed_now),
                )
                assert too_big.status_code == 413

                # Valid signed Slack interactive approve action.
                interaction = {
                    "type": "block_actions",
                    "user": {"id": "U12345", "username": "secops-lead"},
                    "response_url": "https://hooks.slack.com/actions/T00/111/222",
                    "actions": [
                        {
                            "action_id": "zerobom_triage_approve",
                            "value": "PRECVE-2026-WRK11111",
                        }
                    ],
                }
                form_body = urlencode({"payload": json.dumps(interaction)}).encode("utf-8")
                ok_resp = client.post(
                    f"{base_url}/slack/actions",
                    content=form_body,
                    headers=_sign_slack_request(form_body, secret, fixed_now),
                )
                assert ok_resp.status_code == 200
                assert "PRECVE-2026-WRK11111" in ok_resp.json()["text"]

            server.wait_for_pending(timeout=5.0)
            assert server.background_errors == ()
            updated = store.get("PRECVE-2026-WRK11111")
            assert updated is not None
            assert updated.status == TriageStatus.APPROVED
            assert updated.decided_by == "secops-lead"
            assert updated.last_match_count == 1
            assert len(slack_updates) == 1
            assert slack_updates[0]["replace_original"] is True
            assert "APPROVED" in slack_updates[0]["text"]
        finally:
            server.shutdown()
            thread.join(timeout=3.0)
            server.close()
            resp_client.close()

        # Tampered response_url outside Slack hosts is rejected cleanly.
        with pytest.raises(AlertDeliveryError, match="allowlist"):
            post_slack_response_url(
                "https://evil.example/steal-result",
                {"text": "hi"},
                dns_resolver=_public_dns,
            )

    def test_socket_mode_worker_fails_cleanly_without_slack_sdk(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = TriageQueueStore(tmp_path / "sm.sqlite")
        handler = TriageActionHandler(store)
        real_import = importlib.import_module

        def _missing_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name.startswith("slack_sdk"):
                raise ImportError("No module named 'slack_sdk'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(importlib, "import_module", _missing_import)
        with pytest.raises(RuntimeError, match="slack-sdk"):
            run_socket_mode_worker(
                handler,
                app_token=_cred("xapp"),
                bot_token=_cred("xoxb"),
            )


# ---------------------------------------------------------------------------
# 5. CLI Triage Subcommands & Alerting Flags
# ---------------------------------------------------------------------------


class _FakeTriageExtractor:
    def __enter__(self) -> _FakeTriageExtractor:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    @property
    def model_name(self) -> str:
        return "test-triage-model"

    @property
    def prompt_version(self) -> str:
        return "v1.4"

    def extract(self, article: RawArticle, *, known_aliases: Any = ()) -> ExtractedAdvisory:
        del known_aliases
        return ExtractedAdvisory(
            article_url=article.url,
            title=article.title,
            summary="Requests netrc disclosure prior to 2.31.0",
            claims=(
                ExtractedPackageClaim(
                    raw_package_name="requests",
                    ecosystem="pypi",
                    version_constraints=(VersionConstraint(fixed="2.31.0"),),
                    evidence_quote="Python requests prior to 2.31.0 leaks credentials.",
                ),
            ),
        )


class TestTriageCli:
    def test_cli_check_enqueues_triage_then_list_show_approve_and_reject(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sbom_path = _write_sample_sbom(tmp_path / "sbom.cdx.json")
        triage_db = tmp_path / "cli_triage.sqlite"
        html = (
            b"<html><head><title>Requests SSRF</title></head>"
            b"<body>Python requests prior to 2.31.0 leaks credentials.</body></html>"
        )
        transport = httpx.MockTransport(
            lambda req: httpx.Response(200, headers={"Content-Type": "text/html"}, content=html)
        )
        monkeypatch.setattr(
            cli,
            "_create_fetcher",
            lambda: SafeHttpFetcher(
                client=httpx.Client(transport=transport),
                dns_resolver=_public_dns,
            ),
        )
        monkeypatch.setattr(cli, "_create_extractor", lambda: _FakeTriageExtractor())

        res_check = RUNNER.invoke(
            cli.app,
            [
                "check",
                "--url",
                "https://unknown.example.org/requests-post",
                "--tier",
                "unknown",
                "--triage-db",
                str(triage_db),
                "--format",
                "json",
            ],
        )
        assert res_check.exit_code == cli.EXIT_OK

        res_list = RUNNER.invoke(
            cli.app,
            ["triage", "list", "--triage-db", str(triage_db), "--format", "json"],
        )
        assert res_list.exit_code == cli.EXIT_OK
        items = json.loads(res_list.stdout)
        assert len(items) == 1
        triage_id = items[0]["triage_id"]
        assert items[0]["status"] == "pending"

        res_show = RUNNER.invoke(
            cli.app,
            ["triage", "show", triage_id, "--triage-db", str(triage_db)],
        )
        assert res_show.exit_code == cli.EXIT_OK
        assert triage_id in res_show.stdout

        # Approve against local SBOM finds vulnerable requests@2.30.0 -> exit 1!
        res_approve = RUNNER.invoke(
            cli.app,
            [
                "triage",
                "approve",
                triage_id,
                "--triage-db",
                str(triage_db),
                "--sbom",
                str(sbom_path),
                "--actor",
                "cli-reviewer",
                "--format",
                "json",
            ],
        )
        assert res_approve.exit_code == cli.EXIT_VULNERABLE
        assert json.loads(res_approve.stdout)["summary"]["vulnerable_hits"] == 1

        # Enqueue another item directly to test CLI reject command.
        store = TriageQueueStore(triage_db)
        store.enqueue_outcome(
            PipelineOutcome(
                credibility=_make_credibility(RoutingDecision.TRIAGE),
                osv=_make_osv("PRECVE-2026-CLI99999"),
            )
        )
        res_reject = RUNNER.invoke(
            cli.app,
            [
                "triage",
                "reject",
                "PRECVE-2026-CLI99999",
                "--triage-db",
                str(triage_db),
                "--actor",
                "cli-reviewer",
                "--note",
                "False alarm",
            ],
        )
        assert res_reject.exit_code == cli.EXIT_OK
        rejected = store.get("PRECVE-2026-CLI99999")
        assert rejected is not None
        assert rejected.status == TriageStatus.REJECTED

        # Invalid SSRF webhook target exits cleanly with EXIT_ERROR = 2.
        osv_path = tmp_path / "adv.osv.json"
        osv_path.write_text(json.dumps(_make_osv().to_osv_dict()), encoding="utf-8")
        res_bad_hook = RUNNER.invoke(
            cli.app,
            [
                "scan",
                "--osv",
                str(osv_path),
                "--sbom",
                str(sbom_path),
                "--webhook-url",
                "http://169.254.169.254/latest/meta-data/",
            ],
        )
        assert res_bad_hook.exit_code == cli.EXIT_ERROR


# ---------------------------------------------------------------------------
# 6. Phase 2 Hardening Pass Regression Tests (Alerting, Slack & Triage)
# ---------------------------------------------------------------------------


class TestPhase2AlertingAndTriageHardening:
    def test_webhook_and_slack_scrub_secrets_validate_timeout_and_block_dns_rebinding(self) -> None:
        hook_path = "/hooks/private-hook-route"
        hook_query = f"auth={_cred('query')}"
        webhook_url = f"https://alerts.example.org{hook_path}?{hook_query}"
        slack_url = "https://hooks.slack.com/services/T111/B222/SLACK_ROUTING_KEY"

        def _failing_transport(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(
                f"dial failed for {request.url}",
                request=request,
            )

        client = httpx.Client(transport=httpx.MockTransport(_failing_transport))
        notifier = WebhookNotifier(
            webhook_url,
            dns_resolver=_public_dns,
            http_client=client,
        )
        slack_notifier = SlackNotifier(
            slack_url,
            dns_resolver=_public_dns,
            http_client=client,
        )
        try:
            hit_outcome = PipelineOutcome(
                credibility=_make_credibility(RoutingDecision.AUTO),
                osv=_make_osv("PRECVE-2026-REDACT01"),
                matches=(_make_match(1, "PRECVE-2026-REDACT01"),),
            )
            with pytest.raises(AlertDeliveryError) as exc_hook:
                notifier.send_outcome(hit_outcome)
            hook_msg = str(exc_hook.value)
            assert hook_path not in hook_msg
            assert hook_query not in hook_msg
            assert "alerts.example.org" in hook_msg

            with pytest.raises(AlertDeliveryError) as exc_slack:
                slack_notifier.send_outcome(hit_outcome)
            slack_msg = str(exc_slack.value)
            assert "T111" not in slack_msg
            assert "B222" not in slack_msg
            assert "SLACK_ROUTING_KEY" not in slack_msg
            assert "hooks.slack.com" in slack_msg
        finally:
            notifier.close()
            slack_notifier.close()
            client.close()

        # Timeout validation rejects negative/zero/bool timeouts cleanly.
        with pytest.raises(AlertDeliveryError, match="timeout_seconds"):
            WebhookNotifier(webhook_url, timeout_seconds=-1.0, dns_resolver=_public_dns)
        with pytest.raises(AlertDeliveryError, match="timeout_seconds"):
            SlackNotifier(slack_url, timeout_seconds=0.0, dns_resolver=_public_dns)

        # DNS rebinding TOCTOU: public at __init__, private IP when send_outcome executes.
        dns_answers: list[tuple[str, ...]] = [("93.184.216.34",), ("169.254.169.254",)]
        http_calls: list[httpx.Request] = []

        def _rebind_dns(_host: str, _port: int) -> tuple[str, ...]:
            return dns_answers.pop(0) if dns_answers else ("169.254.169.254",)

        client_no_send = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: (http_calls.append(req), httpx.Response(200, text="ok"))[1]
            )
        )
        rebind_hook = WebhookNotifier(
            webhook_url,
            dns_resolver=_rebind_dns,
            http_client=client_no_send,
        )
        try:
            hit = PipelineOutcome(
                credibility=_make_credibility(RoutingDecision.AUTO),
                osv=_make_osv("PRECVE-2026-TOCTOU01"),
                matches=(_make_match(1, "PRECVE-2026-TOCTOU01"),),
            )
            with pytest.raises(AlertDeliveryError, match="non-public"):
                rebind_hook.send_outcome(hit)
            assert len(http_calls) == 0
        finally:
            rebind_hook.close()

        slack_answers: list[tuple[str, ...]] = [("93.184.216.34",), ("10.0.0.5",)]
        rebind_slack = SlackNotifier(
            slack_url,
            dns_resolver=lambda _h, _p: slack_answers.pop(0),
            http_client=client_no_send,
        )
        try:
            with pytest.raises(AlertDeliveryError, match="non-public"):
                rebind_slack.send_outcome(hit)
            assert len(http_calls) == 0
        finally:
            rebind_slack.close()
            client_no_send.close()

    def test_slack_payload_bounds_and_backtick_sanitization(self) -> None:
        assert escape_slack_mrkdwn("abcdef", max_length=2) == "ab"
        assert escape_slack_mrkdwn("<!channel>", max_length=3) == "&lt"

        # 1) Backtick neutralization verified on a short line below the 250-char line cap.
        short_match = MatchResult(
            advisory_id="PRECVE-2026-BACKTICK",
            component_purl="pkg:pypi/pkg-`name",
            installed_version="1.0.0`beta",
            matched_purl="pkg:pypi/pkg-name",
            ecosystem="PyPI",
            is_vulnerable=True,
            matched_range="<2.0.0",
            fixed_versions=("2.0.0`rc1",),
            evidence_quote="Proof quote",
            sbom_source="svc-0/sbom.cdx.json",
            asset=AssetRef(
                asset_id="cluster/`svc-0",
                asset_type="container",
                backend="local_`sbom",
                location="loc-0",
            ),
        )
        short_payload = build_slack_auto_payload(
            PipelineOutcome(
                credibility=_make_credibility(RoutingDecision.AUTO),
                osv=_make_osv("PRECVE-2026-BACKTICK"),
                matches=(short_match,),
            )
        )
        short_assets = next(
            b
            for b in short_payload["blocks"]
            if b["type"] == "section" and "text" in b and "*Affected Assets:*" in b["text"]["text"]
        )["text"]["text"]
        assert "local_'sbom" in short_assets
        assert "cluster/'svc-0" in short_assets
        assert "pkg-'name" in short_assets
        assert "1.0.0'beta" in short_assets
        assert "2.0.0'rc1" in short_assets

        # 2) Long advisory ID + 12 oversized matches stay under Slack header & section caps.
        long_adv_id = "PRECVE-2026-" + ("`ADV" * 60)
        long_matches = tuple(
            MatchResult(
                advisory_id=long_adv_id,
                component_purl=f"pkg:pypi/pkg-`name-{i}-" + ("x" * 180),
                installed_version="1.0.0`beta",
                matched_purl="pkg:pypi/pkg-name",
                ecosystem="PyPI",
                is_vulnerable=True,
                matched_range="<2.0.0",
                fixed_versions=("2.0.0`rc1",),
                evidence_quote="Proof quote",
                sbom_source=f"svc-{i}/sbom.cdx.json",
                asset=AssetRef(
                    asset_id=f"cluster/`svc-{i}-" + ("a" * 180),
                    asset_type="container",
                    backend="local_`sbom",
                    location=f"loc-{i}",
                ),
            )
            for i in range(12)
        )
        outcome = PipelineOutcome(
            credibility=_make_credibility(RoutingDecision.AUTO),
            osv=_make_osv(long_adv_id),
            matches=long_matches,
        )
        payload = build_slack_auto_payload(outcome)
        header_block = next(b for b in payload["blocks"] if b["type"] == "header")
        assert len(header_block["text"]["text"]) <= 150

        asset_section = next(
            b
            for b in payload["blocks"]
            if b["type"] == "section" and "text" in b and "*Affected Assets:*" in b["text"]["text"]
        )
        rendered_assets = asset_section["text"]["text"]
        assert len(rendered_assets) <= 2950
        assert "more vulnerable asset hit(s)" in rendered_assets

    def test_triage_store_cross_channel_notification_isolation(self, tmp_path: Path) -> None:
        store = TriageQueueStore(tmp_path / "triage.sqlite")
        outcome = PipelineOutcome(
            credibility=_make_credibility(RoutingDecision.TRIAGE),
            osv=_make_osv("PRECVE-2026-CHAN0001"),
        )
        store.enqueue_outcome(outcome)

        assert store.should_notify("PRECVE-2026-CHAN0001", "digest-v1", channel="webhook") is True
        store.mark_notified("PRECVE-2026-CHAN0001", "digest-v1", channel="webhook")

        # Same channel + same digest suppresses repeat alerts; a separate channel stays enabled.
        assert store.should_notify("PRECVE-2026-CHAN0001", "digest-v1", channel="webhook") is False
        assert store.should_notify("PRECVE-2026-CHAN0001", "digest-v1", channel="slack") is True

    def test_triage_action_handler_serializes_concurrent_approve(self, tmp_path: Path) -> None:
        sbom_path = _write_sample_sbom(tmp_path / "sbom.cdx.json")
        store = TriageQueueStore(tmp_path / "triage.sqlite")
        store.enqueue_outcome(
            PipelineOutcome(
                credibility=_make_credibility(RoutingDecision.TRIAGE),
                osv=_make_osv("PRECVE-2026-CONC0001"),
            )
        )

        factory_calls = 0
        factory_lock = threading.Lock()
        entered_scan = threading.Event()
        release_scan = threading.Event()

        def _backend_factory() -> LocalSbomBackend:
            nonlocal factory_calls
            with factory_lock:
                factory_calls += 1
            entered_scan.set()
            release_scan.wait(timeout=2.0)
            return LocalSbomBackend(sbom_path)

        handler = TriageActionHandler(store, backend_factory=_backend_factory)

        with ThreadPoolExecutor(max_workers=2) as pool:
            fut_a = pool.submit(handler.approve, "PRECVE-2026-CONC0001", actor="reviewer-a")
            assert entered_scan.wait(timeout=2.0)
            fut_b = pool.submit(handler.approve, "PRECVE-2026-CONC0001", actor="reviewer-b")
            release_scan.set()
            res_a = fut_a.result(timeout=3.0)
            res_b = fut_b.result(timeout=3.0)

        assert factory_calls == 1
        already_flags = [res_a.already_decided, res_b.already_decided]
        assert sorted(already_flags) == [False, True]

    def test_triage_webhook_server_failure_feedback_503_and_slowloris_timeout(
        self, tmp_path: Path
    ) -> None:
        store = TriageQueueStore(tmp_path / "triage.sqlite")
        store.enqueue_outcome(
            PipelineOutcome(
                credibility=_make_credibility(RoutingDecision.TRIAGE),
                osv=_make_osv("PRECVE-2026-SRV00001"),
            )
        )

        def _failing_backend() -> LocalSbomBackend:
            raise BackendError("simulated remote inventory outage")

        response_posts: list[dict[str, Any]] = []
        response_posted = threading.Event()

        def _resp_transport(request: httpx.Request) -> httpx.Response:
            response_posts.append(json.loads(request.content.decode("utf-8")))
            response_posted.set()
            return httpx.Response(200, text="ok")

        secret_val = _cred("slack-signing")
        fixed_ts = 1_780_000_000
        handler = TriageActionHandler(store, backend_factory=_failing_backend)

        with pytest.raises(TriageError, match="timeout_seconds"):
            TriageWebhookServer(
                handler,
                signing_secret=secret_val,
                host="127.0.0.1",
                port=0,
                request_timeout_seconds=0.1,
                dns_resolver=_public_dns,
            )

        with (
            httpx.Client(transport=httpx.MockTransport(_resp_transport)) as resp_client,
            TriageWebhookServer(
                handler,
                signing_secret=secret_val,
                host="127.0.0.1",
                port=0,
                request_timeout_seconds=0.5,
                max_concurrent_requests=1,
                dns_resolver=_public_dns,
                response_http_client=resp_client,
                now_fn=lambda: fixed_ts,
            ) as server,
        ):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://127.0.0.1:{server.server_port}"
            try:
                # 1) Background BackendError posts ephemeral failure feedback to response_url.
                payload_dict = {
                    "type": "block_actions",
                    "user": {"username": "alice"},
                    "response_url": "https://hooks.slack.com/actions/T1/B2/resp-fail",
                    "actions": [
                        {
                            "action_id": "zerobom_triage_approve",
                            "value": "PRECVE-2026-SRV00001",
                        }
                    ],
                }
                form_body = urlencode({"payload": json.dumps(payload_dict)}).encode("utf-8")
                resp_ack = httpx.post(
                    f"{base_url}/slack/actions",
                    content=form_body,
                    headers=_sign_slack_request(form_body, secret_val, fixed_ts),
                    timeout=3.0,
                )
                assert resp_ack.status_code == 200
                server.wait_for_pending(timeout=3.0)
                assert response_posted.wait(timeout=2.0)
                assert any(
                    "failed" in p.get("text", "").lower()
                    and "PRECVE-2026-SRV00001" in p.get("text", "")
                    for p in response_posts
                )

                # 2) Concurrency semaphore full -> immediate HTTP 503 server_busy.
                assert server._inflight_sem.acquire(blocking=False) is True
                try:
                    resp_busy = httpx.post(
                        f"{base_url}/slack/actions",
                        content=form_body,
                        headers=_sign_slack_request(form_body, secret_val, fixed_ts),
                        timeout=3.0,
                    )
                    assert resp_busy.status_code == 503
                    assert resp_busy.json()["error"] == "server_busy"
                finally:
                    server._inflight_sem.release()

                # 3) Stalled Slowloris TCP client times out cleanly without hanging worker thread.
                with socket.create_connection(
                    ("127.0.0.1", server.server_port), timeout=3.0
                ) as sock:
                    sock.settimeout(3.0)
                    sock.sendall(
                        b"POST /slack/actions HTTP/1.1\r\n"
                        b"Host: 127.0.0.1\r\n"
                        b"Content-Length: 4096\r\n\r\n"
                        b"partial="
                    )
                    assert sock.recv(1024) == b""
            finally:
                server.shutdown()
                thread.join(timeout=2.0)

    def test_socket_mode_worker_handles_backend_error_and_close(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = TriageQueueStore(tmp_path / "triage.sqlite")
        store.enqueue_outcome(
            PipelineOutcome(
                credibility=_make_credibility(RoutingDecision.TRIAGE),
                osv=_make_osv("PRECVE-2026-SM000001"),
            )
        )

        handler = TriageActionHandler(
            store,
            backend_factory=lambda: (_ for _ in ()).throw(BackendError("socket-mode scan error")),
        )

        acked_envelopes: list[str] = []
        sent_updates: list[tuple[str, dict[str, Any]]] = []
        closed_clients: list[bool] = []

        class _FakeWebClient:
            def __init__(self, *, token: str) -> None:
                self.token = token

        class _FakeSocketModeClient:
            def __init__(self, *, app_token: str, web_client: Any) -> None:
                self.app_token = app_token
                self.web_client = web_client
                self.socket_mode_request_listeners: list[Any] = []
                self.connected = False

            def connect(self) -> None:
                self.connected = True

            def send_socket_mode_response(self, resp: Any) -> None:
                acked_envelopes.append(str(resp.envelope_id))

            def close(self) -> None:
                closed_clients.append(True)
                self.connected = False

        class _FakeSocketModeResponse:
            def __init__(self, *, envelope_id: str) -> None:
                self.envelope_id = envelope_id

        fake_clients: list[_FakeSocketModeClient] = []

        def _make_sm_client(*, app_token: str, web_client: Any) -> _FakeSocketModeClient:
            inst = _FakeSocketModeClient(app_token=app_token, web_client=web_client)
            fake_clients.append(inst)
            return inst

        fake_web_mod = types.SimpleNamespace(WebClient=_FakeWebClient)
        fake_sm_mod = types.SimpleNamespace(SocketModeClient=_make_sm_client)
        fake_sm_resp_mod = types.SimpleNamespace(SocketModeResponse=_FakeSocketModeResponse)

        real_import_module = importlib.import_module

        def _fake_import(name: str, package: str | None = None) -> Any:
            if name == "slack_sdk.web":
                return fake_web_mod
            if name == "slack_sdk.socket_mode":
                return fake_sm_mod
            if name == "slack_sdk.socket_mode.response":
                return fake_sm_resp_mod
            return real_import_module(name, package)

        monkeypatch.setattr(importlib, "import_module", _fake_import)
        monkeypatch.setattr(
            "zerobom.triage.server.post_slack_response_url",
            lambda url, payload, **_kw: sent_updates.append((url, dict(payload))),
        )

        handle = run_socket_mode_worker(
            handler,
            app_token=_cred("xapp-token"),
            bot_token=_cred("xoxb-token"),
            dns_resolver=_public_dns,
        )
        assert len(fake_clients) == 1
        sm_client = fake_clients[0]
        assert sm_client.connected is True

        envelope = types.SimpleNamespace(
            type="interactive",
            envelope_id="env-123",
            payload={
                "type": "block_actions",
                "user": {"username": "bob"},
                "response_url": "https://hooks.slack.com/actions/T1/B2/sm-resp",
                "actions": [
                    {"action_id": "zerobom_triage_approve", "value": "PRECVE-2026-SM000001"}
                ],
            },
        )
        sm_client.socket_mode_request_listeners[0](sm_client, envelope)
        assert acked_envelopes == ["env-123"]
        assert len(sent_updates) == 1
        assert "failed" in sent_updates[0][1]["text"].lower()
        assert "PRECVE-2026-SM000001" in sent_updates[0][1]["text"]

        handle.close()
        assert handle.is_set() is True
        assert closed_clients == [True]
        assert sm_client.connected is False

    def test_cli_triage_markup_escaping_sarif_rejection_and_missing_sbom_fail_closed(
        self, tmp_path: Path
    ) -> None:
        triage_db = tmp_path / "triage.sqlite"
        store = TriageQueueStore(triage_db)
        outcome = PipelineOutcome(
            article=RawArticle(
                url="https://unknown.example.org/markup-trap",
                title="[red]X[/red]",
                published_at=PUBLISHED_AT,
                body="Python requests prior to 2.31.0.",
                source_name="[b]Src[/b]",
                source_tier=SourceTier.UNKNOWN,
            ),
            credibility=_make_credibility(RoutingDecision.TRIAGE),
            osv=_make_osv("PRECVE-2026-CLIGUARD"),
        )
        store.enqueue_outcome(outcome)

        # 1) triage list renders literal Rich markup without interpreting tags.
        res_list = RUNNER.invoke(
            cli.app,
            ["triage", "list", "--triage-db", str(triage_db)],
        )
        assert res_list.exit_code == cli.EXIT_OK
        assert "[red]X[/red]" in res_list.stdout
        assert "[b]Src[/b]" in res_list.stdout

        # 2) triage list & triage show reject --format sarif cleanly.
        res_list_sarif = RUNNER.invoke(
            cli.app,
            ["triage", "list", "--triage-db", str(triage_db), "--format", "sarif"],
        )
        assert res_list_sarif.exit_code == cli.EXIT_ERROR
        res_show_sarif = RUNNER.invoke(
            cli.app,
            [
                "triage",
                "show",
                "PRECVE-2026-CLIGUARD",
                "--triage-db",
                str(triage_db),
                "--format",
                "sarif",
            ],
        )
        assert res_show_sarif.exit_code == cli.EXIT_ERROR

        # 3) triage approve & triage-worker fail closed without --sbom when backend=local_sbom.
        res_approve_no_sbom = RUNNER.invoke(
            cli.app,
            ["triage", "approve", "PRECVE-2026-CLIGUARD", "--triage-db", str(triage_db)],
        )
        assert res_approve_no_sbom.exit_code == cli.EXIT_ERROR
        persisted = store.get("PRECVE-2026-CLIGUARD")
        assert persisted is not None
        assert persisted.status == TriageStatus.PENDING

        res_worker_no_sbom = RUNNER.invoke(
            cli.app,
            [
                "triage-worker",
                "--triage-db",
                str(triage_db),
                "--signing-secret",
                _cred("secret"),
            ],
        )
        assert res_worker_no_sbom.exit_code == cli.EXIT_ERROR

    def test_webhook_and_slack_notifiers_disable_trust_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from zerobom.outputs import SlackNotifier, WebhookNotifier

        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
        with (
            WebhookNotifier(
                "https://alerts.example.org/hook",
                dns_resolver=lambda _h, _p: ("93.184.216.34",),
            ) as wh,
            SlackNotifier(
                "https://hooks.slack.com/services/T1/B2/x3",
                dns_resolver=lambda _h, _p: ("93.184.216.34",),
            ) as sk,
        ):
            assert wh._client.trust_env is False
            assert sk._client.trust_env is False
