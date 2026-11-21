"""Output formatters and outbound alerting (Rich, JSON, SARIF, Webhook, Slack, GitHub)."""

from zerobom.outputs.github_issue import (
    DEFAULT_GITHUB_API_URL,
    DEFAULT_ISSUE_LABELS,
    GitHubIssueError,
    GitHubIssueSyncer,
    IssueSyncResult,
    RenderedGitHubIssue,
    build_issue_marker,
    render_github_issue,
    sanitize_github_markdown,
    sanitize_table_cell,
    validate_github_repo,
)
from zerobom.outputs.json_out import build_json_report, render_json_outcomes
from zerobom.outputs.sarif import build_sarif_log, render_sarif
from zerobom.outputs.slack import (
    SLACK_WEBHOOK_HOSTS,
    SlackNotifier,
    build_slack_auto_payload,
    build_slack_triage_decision_payload,
    build_slack_triage_payload,
    escape_slack_mrkdwn,
)
from zerobom.outputs.terminal import render_terminal_outcomes
from zerobom.outputs.webhook import (
    AlertDeliveryError,
    AlertDeliveryResult,
    WebhookNotifier,
    build_webhook_payload,
    classify_alert_event,
    sign_webhook_body,
    validate_webhook_url,
)

__all__ = [
    "DEFAULT_GITHUB_API_URL",
    "DEFAULT_ISSUE_LABELS",
    "SLACK_WEBHOOK_HOSTS",
    "AlertDeliveryError",
    "AlertDeliveryResult",
    "GitHubIssueError",
    "GitHubIssueSyncer",
    "IssueSyncResult",
    "RenderedGitHubIssue",
    "SlackNotifier",
    "WebhookNotifier",
    "build_issue_marker",
    "build_json_report",
    "build_sarif_log",
    "build_slack_auto_payload",
    "build_slack_triage_decision_payload",
    "build_slack_triage_payload",
    "build_webhook_payload",
    "classify_alert_event",
    "escape_slack_mrkdwn",
    "render_github_issue",
    "render_json_outcomes",
    "render_sarif",
    "render_terminal_outcomes",
    "sanitize_github_markdown",
    "sanitize_table_cell",
    "sign_webhook_body",
    "validate_github_repo",
    "validate_webhook_url",
]
