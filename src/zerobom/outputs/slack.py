"""Slack Block Kit message formatter and host-pinned outbound webhook notifier."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from typing import Any

import httpx

from zerobom.backends import BackendError
from zerobom.backends._http import validate_timeout_seconds
from zerobom.ingest.fetcher import DnsResolver, default_dns_resolver
from zerobom.models import PipelineOutcome
from zerobom.outputs.webhook import (
    AlertDeliveryError,
    AlertDeliveryResult,
    _post_json_webhook,
    classify_alert_event,
    extract_safe_source_url,
    extract_verified_quotes,
    redact_url_for_repr,
    validate_webhook_url,
)

SLACK_WEBHOOK_HOSTS: frozenset[str] = frozenset({"hooks.slack.com", "hooks.slack-gov.com"})
_MAX_SLACK_ASSETS_SHOWN = 10
_MAX_SLACK_SECTION_CHARS = 2950
_MAX_SLACK_HEADER_CHARS = 150


def _strip_backticks(value: str) -> str:
    """Neutralize backticks inside inline Slack code spans to prevent breakout."""
    return value.replace("`", "'")


def _truncate_plain_text(text: str, max_length: int) -> str:
    """Bound Slack plain_text header fields cleanly without mid-word overflow."""
    cleaned = "".join(ch for ch in text if ord(ch) >= 32 and ord(ch) != 127).strip()
    if max_length < 4:
        return cleaned[:max_length]
    if len(cleaned) > max_length:
        return cleaned[: max_length - 3].rstrip() + "..."
    return cleaned


def escape_slack_mrkdwn(text: str, *, max_length: int = 2800) -> str:
    r"""Sanitize untrusted text for Slack mrkdwn to neutralize mention/link injection.

    Strips ASCII control characters (except ``\n`` and ``\t``), escapes ``&``, ``<``, and
    ``>`` (blocking ``<!channel>``, ``<!here>``, ``<@U...>``, and spoofed links), and bounds
    rendered length.
    """
    cleaned = "".join(ch for ch in text if ch in {"\n", "\t"} or (ord(ch) >= 32 and ord(ch) != 127))
    escaped = cleaned.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if max_length < 4:
        return escaped[:max_length]
    if len(escaped) > max_length:
        return escaped[: max_length - 3].rstrip() + "..."
    return escaped


def build_slack_auto_payload(outcome: PipelineOutcome) -> dict[str, Any]:
    """Build a consolidated Slack Block Kit alert payload for matched vulnerabilities."""
    osv = outcome.osv
    advisory_id = escape_slack_mrkdwn(
        _strip_backticks(osv.id if osv is not None else "unknown"),
        max_length=120,
    )
    summary = escape_slack_mrkdwn(
        osv.summary
        if osv is not None
        else (outcome.advisory.summary if outcome.advisory is not None else "Pre-CVE advisory"),
        max_length=500,
    )
    cred = outcome.credibility
    score_label = f"{cred.composite_score:.2f} ({cred.routing.value.upper()})" if cred else "SCAN"

    vulnerable = outcome.vulnerable_matches
    asset_lines: list[str] = []
    header_prefix = "*Affected Assets:*\n"
    reserve_overflow_chars = 80
    used_chars = len(header_prefix)

    for match in vulnerable[:_MAX_SLACK_ASSETS_SHOWN]:
        backend_name = _strip_backticks(
            match.asset.backend if match.asset is not None else "local_sbom"
        )
        asset_id = _strip_backticks(
            match.asset.asset_id if match.asset is not None else (match.sbom_source or "sbom")
        )
        comp_purl = _strip_backticks(match.component_purl)
        installed_ver = _strip_backticks(match.installed_version)
        fixed_str = (
            f" (fixed: {_strip_backticks(', '.join(match.fixed_versions))})"
            if match.fixed_versions
            else ""
        )
        raw_line = f"• `[{backend_name}]` `{asset_id}` — `{comp_purl}` `{installed_ver}`{fixed_str}"
        safe_line = escape_slack_mrkdwn(raw_line, max_length=250)
        line_cost = len(safe_line) + (1 if asset_lines else 0)
        if used_chars + line_cost + reserve_overflow_chars > _MAX_SLACK_SECTION_CHARS:
            break
        asset_lines.append(safe_line)
        used_chars += line_cost

    overflow = len(vulnerable) - len(asset_lines)
    if overflow > 0:
        asset_lines.append(f"• _... and {overflow} more vulnerable asset hit(s)._")

    header_text = _truncate_plain_text(
        f"zerobom ALERT: {advisory_id} ({len(vulnerable)} hit(s))",
        _MAX_SLACK_HEADER_CHARS,
    )
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": header_text,
                "emoji": False,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Advisory:*\n`{advisory_id}`"},
                {"type": "mrkdwn", "text": f"*Credibility:*\n`{score_label}`"},
            ],
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Summary:*\n{summary}"},
        },
    ]

    if asset_lines:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Affected Assets:*\n" + "\n".join(asset_lines),
                },
            }
        )

    quotes = extract_verified_quotes(outcome)
    if quotes:
        safe_quote = escape_slack_mrkdwn(quotes[0], max_length=700)
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Verified Quote:*\n> {safe_quote}"},
            }
        )

    source_url = extract_safe_source_url(outcome)
    if source_url is not None:
        safe_url = escape_slack_mrkdwn(source_url, max_length=1000)
        blocks.append(
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"Source: {safe_url}"}],
            }
        )

    return {
        "text": f"zerobom ALERT: {advisory_id} matched {len(vulnerable)} vulnerable asset(s).",
        "blocks": blocks,
    }


def build_slack_triage_payload(
    outcome: PipelineOutcome,
    *,
    triage_id: str | None = None,
    include_interactive_buttons: bool = True,
) -> dict[str, Any]:
    """Build a Slack Block Kit review notification for ``TRIAGE`` advisories."""
    osv = outcome.osv
    advisory_id = escape_slack_mrkdwn(
        _strip_backticks(osv.id if osv is not None else "unknown"),
        max_length=120,
    )
    summary = escape_slack_mrkdwn(
        osv.summary
        if osv is not None
        else (outcome.advisory.summary if outcome.advisory is not None else "Pre-CVE review"),
        max_length=500,
    )
    cred = outcome.credibility
    score_val = f"{cred.composite_score:.2f}" if cred is not None else "N/A"
    tier_val = cred.source_tier.value if cred is not None else "unknown"

    pkg_list = (
        ", ".join(f"`{_strip_backticks(aff.package.purl)}`" for aff in osv.affected[:5])
        if osv is not None
        else "`unknown`"
    )
    safe_pkg_list = escape_slack_mrkdwn(pkg_list, max_length=400)

    cli_approve = (
        f"zerobom triage approve {_strip_backticks(triage_id)}"
        if triage_id
        else f"zerobom scan --osv {advisory_id}.osv.json --sbom <path-to-sbom>"
    )
    safe_cmd = escape_slack_mrkdwn(_strip_backticks(cli_approve), max_length=250)

    triage_header = _truncate_plain_text(
        f"zerobom TRIAGE Review: {advisory_id}",
        _MAX_SLACK_HEADER_CHARS,
    )
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": triage_header,
                "emoji": False,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Score / Tier:*\n`{score_val}` (`{tier_val}`)"},
                {"type": "mrkdwn", "text": f"*Packages:*\n{safe_pkg_list}"},
            ],
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Summary:*\n{summary}"},
        },
    ]

    quotes = extract_verified_quotes(outcome)
    if quotes:
        safe_quote = escape_slack_mrkdwn(quotes[0], max_length=700)
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Verified Quote:*\n> {safe_quote}"},
            }
        )

    blocks.append(
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Review Command:*\n`{safe_cmd}`",
            },
        }
    )

    if triage_id is not None and include_interactive_buttons:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve & Scan", "emoji": False},
                        "style": "primary",
                        "action_id": "zerobom_triage_approve",
                        "value": triage_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Reject", "emoji": False},
                        "style": "danger",
                        "action_id": "zerobom_triage_reject",
                        "value": triage_id,
                    },
                ],
            }
        )

    source_url = extract_safe_source_url(outcome)
    if source_url is not None:
        safe_url = escape_slack_mrkdwn(source_url, max_length=1000)
        blocks.append(
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"Source: {safe_url}"}],
            }
        )

    return {
        "text": f"zerobom TRIAGE Review required for {advisory_id}.",
        "blocks": blocks,
    }


def build_slack_triage_decision_payload(
    *,
    advisory_id: str,
    status: str,
    actor: str,
    match_count: int = 0,
    already_decided: bool = False,
    note: str | None = None,
) -> dict[str, Any]:
    """Build a Block Kit ``replace_original`` update payload after human triage decision."""
    safe_adv = escape_slack_mrkdwn(advisory_id, max_length=120)
    safe_actor = escape_slack_mrkdwn(actor, max_length=120)
    safe_status = escape_slack_mrkdwn(status.upper(), max_length=32)

    if already_decided:
        summary_line = (
            f"*{safe_adv}* was already `{safe_status}` previously (no duplicate action taken)."
        )
    elif status.lower() == "approved":
        summary_line = (
            f"*{safe_adv}* marked *APPROVED* by `{safe_actor}` — "
            f"inventory scan found *{match_count}* vulnerable asset(s)."
        )
    else:
        summary_line = f"*{safe_adv}* marked *REJECTED* by `{safe_actor}`."

    if note:
        summary_line += f"\nNote: {escape_slack_mrkdwn(note, max_length=300)}"

    return {
        "replace_original": True,
        "text": summary_line,
        "blocks": [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": summary_line},
            }
        ],
    }


class SlackNotifier:
    """Host-pinned Slack Incoming Webhook client sending sanitized Block Kit payloads."""

    def __init__(
        self,
        webhook_url: str,
        *,
        allowed_hosts: frozenset[str] = SLACK_WEBHOOK_HOSTS,
        timeout_seconds: float = 10.0,
        dns_resolver: DnsResolver = default_dns_resolver,
        http_client: httpx.Client | None = None,
    ) -> None:
        """Initialize a Slack Incoming Webhook notifier pinned to Slack webhook hosts."""
        self._webhook_url = validate_webhook_url(
            webhook_url,
            allow_insecure_http=False,
            allow_private_targets=False,
            allowed_hosts=allowed_hosts,
            dns_resolver=dns_resolver,
        )
        try:
            self._timeout_seconds = validate_timeout_seconds(timeout_seconds)
        except (BackendError, ValueError) as exc:
            raise AlertDeliveryError(str(exc)) from exc
        self._allowed_hosts = allowed_hosts
        self._dns_resolver = dns_resolver
        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            self._client = httpx.Client(
                timeout=self._timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            )
            self._owns_client = True

    def close(self) -> None:
        """Close the internally managed HTTP client connection pool."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> SlackNotifier:
        """Enter context manager returning self."""
        return self

    def __exit__(self, *_: object) -> None:
        """Close managed HTTP client on context exit."""
        self.close()

    def __repr__(self) -> str:
        """Return a redacted summary without exposing the Slack webhook secret token path."""
        return f"SlackNotifier(target={redact_url_for_repr(self._webhook_url)!r})"

    def send_outcome(
        self,
        outcome: PipelineOutcome,
        *,
        triage_id: str | None = None,
        include_interactive_buttons: bool = True,
        dedup_check: Callable[[str, str], bool] | None = None,
        on_sent: Callable[[str, str], None] | None = None,
    ) -> AlertDeliveryResult:
        """Send a consolidated AUTO or interactive TRIAGE notification to Slack."""
        event_type = classify_alert_event(outcome)
        advisory_id = outcome.osv.id if outcome.osv is not None else None
        if event_type is None:
            return AlertDeliveryResult(
                advisory_id=advisory_id,
                event_type="skipped",
                delivered=False,
                reason="Outcome did not meet Slack alerting thresholds.",
            )

        if event_type == "auto_hit":
            payload = build_slack_auto_payload(outcome)
        else:
            payload = build_slack_triage_payload(
                outcome,
                triage_id=triage_id,
                include_interactive_buttons=include_interactive_buttons,
            )

        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        if (
            event_type == "triage_review"
            and triage_id is not None
            and dedup_check is not None
            and not dedup_check(triage_id, digest)
        ):
            return AlertDeliveryResult(
                advisory_id=advisory_id,
                event_type="skipped",
                delivered=False,
                digest=digest,
                reason=f"Duplicate Slack triage alert suppressed for {triage_id}.",
            )

        validate_webhook_url(
            self._webhook_url,
            allow_insecure_http=False,
            allow_private_targets=False,
            allowed_hosts=self._allowed_hosts,
            dns_resolver=self._dns_resolver,
        )

        status = _post_json_webhook(
            self._client,
            self._webhook_url,
            payload,
            backend_name="slack",
        )

        if event_type == "triage_review" and triage_id is not None and on_sent is not None:
            on_sent(triage_id, digest)

        return AlertDeliveryResult(
            advisory_id=advisory_id,
            event_type=event_type,
            delivered=True,
            status_code=status,
            digest=digest,
        )

    def send_outcomes(
        self,
        outcomes: Sequence[PipelineOutcome],
        *,
        triage_ids: Mapping[str, str] | None = None,
        include_interactive_buttons: bool = True,
        dedup_check: Callable[[str, str], bool] | None = None,
        on_sent: Callable[[str, str], None] | None = None,
    ) -> tuple[AlertDeliveryResult, ...]:
        """Deliver Slack notifications across a sequence of :class:`PipelineOutcome` entries."""
        results: list[AlertDeliveryResult] = []
        for outcome in outcomes:
            adv_id = outcome.osv.id if outcome.osv is not None else None
            triage_id = triage_ids.get(adv_id) if (triage_ids and adv_id) else None
            results.append(
                self.send_outcome(
                    outcome,
                    triage_id=triage_id,
                    include_interactive_buttons=include_interactive_buttons,
                    dedup_check=dedup_check,
                    on_sent=on_sent,
                )
            )
        return tuple(results)
