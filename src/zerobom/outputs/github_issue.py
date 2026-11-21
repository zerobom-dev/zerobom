"""Idempotent, XSS-hardened GitHub Issue creation and synchronization for ``zerobom``."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Any, Literal

import httpx
from pydantic import Field

from zerobom._version import DEFAULT_USER_AGENT
from zerobom.backends import BackendError
from zerobom.backends._http import (
    REDIRECT_STATUS_CODES,
    read_bounded_response,
    validate_api_base_url,
    validate_no_control_chars,
    validate_timeout_seconds,
)
from zerobom.models import OsvAffected, PipelineOutcome, StrictModel
from zerobom.outputs.webhook import (
    AlertDeliveryError,
    classify_alert_event,
    extract_safe_source_url,
    extract_verified_quotes,
)
from zerobom.verify.osv_compiler import _format_affected_ranges

DEFAULT_GITHUB_API_URL = "https://api.github.com"
DEFAULT_ISSUE_LABELS: tuple[str, ...] = ("zerobom", "security")
MAX_GITHUB_RESPONSE_BYTES = 2_097_152
MAX_OPEN_ISSUE_PAGES = 10
MAX_ISSUE_BODY_CHARS = 60_000
MAX_RENDERED_MATCHES = 50

_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,98}[A-Za-z0-9])?$|^[A-Za-z0-9]$")
_REPO_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_SAFE_ADVISORY_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_MARKER_RE = re.compile(r"<!--\s*zerobom:advisory-id:([A-Za-z0-9._:-]{1,128})\s*-->")
_MENTION_RE = re.compile(r"(?<![A-Za-z0-9_])@([A-Za-z0-9][A-Za-z0-9_/-]*)")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE_RUN_RE = re.compile(r"[\r\n\t]+")


class GitHubIssueError(AlertDeliveryError):
    """Raised when GitHub repository validation or REST issue synchronization fails."""


class RenderedGitHubIssue(StrictModel):
    """Deterministic, sanitized GitHub Issue payload derived from a verified outcome.

    Attributes:
        advisory_id: Canonical OSV/PRECVE advisory identifier.
        event_type: Actionable event classification (``auto_hit`` or ``triage_review``).
        marker: Hidden HTML comment marker used for idempotent issue lookup.
        title: Bounded single-line GitHub issue title.
        body: Sanitized GitHub Flavored Markdown body ending with ``marker``.
        labels: Issue labels applied when creating a new issue.
    """

    advisory_id: str = Field(min_length=1, max_length=128)
    event_type: Literal["auto_hit", "triage_review"]
    marker: str = Field(min_length=1)
    title: str = Field(min_length=1, max_length=256)
    body: str = Field(min_length=1, max_length=65_000)
    labels: tuple[str, ...] = DEFAULT_ISSUE_LABELS


class IssueSyncResult(StrictModel):
    """Outcome summary returned by :meth:`GitHubIssueSyncer.sync_outcome`.

    Attributes:
        advisory_id: Advisory identifier evaluated during sync (or ``unknown`` if absent).
        action: Sync action taken (created, updated, unchanged, skipped, or dry-run).
        issue_number: GitHub issue number if created, updated, or matched.
        issue_url: Web URL (``html_url``) of the GitHub issue if available.
        reason: Optional human-readable explanation when skipped.
    """

    advisory_id: str
    action: Literal[
        "created",
        "updated",
        "unchanged",
        "skipped",
        "dry_run_create",
        "dry_run_update",
    ]
    issue_number: int | None = None
    issue_url: str | None = None
    reason: str | None = None


def _validate_safe_text(value: str, *, field_name: str, allow_empty: bool = False) -> str:
    """Validate bounded untrusted text without control chars, wrapping errors cleanly."""
    try:
        return validate_no_control_chars(
            value,
            field_name=field_name,
            allow_empty=allow_empty,
        )
    except (BackendError, ValueError) as exc:
        raise GitHubIssueError(str(exc)) from exc


def _normalize_labels(labels: Sequence[str]) -> tuple[str, ...]:
    """Validate and deduplicate GitHub issue labels while enforcing control-char safety."""
    cleaned = tuple(
        dict.fromkeys(
            validated
            for lbl in labels
            if (validated := _validate_safe_text(lbl, field_name="label", allow_empty=True).strip())
        )
    )
    return cleaned or DEFAULT_ISSUE_LABELS


def validate_github_repo(repo: str) -> tuple[str, str]:
    """Validate and split a ``owner/repo`` GitHub repository slug.

    Args:
        repo: Repository slug in ``owner/name`` format.

    Returns:
        Validated ``(owner, name)`` tuple free of traversal or control characters.

    Raises:
        GitHubIssueError: If ``repo`` is malformed or contains unsafe characters.
    """
    cleaned = _validate_safe_text(repo, field_name="github_repo").strip()
    if len(cleaned) > 205 or "\\" in cleaned or "/" not in cleaned:
        raise GitHubIssueError(f"Invalid GitHub repository slug: {repo!r} (expected owner/repo).")
    parts = cleaned.split("/")
    if len(parts) != 2:
        raise GitHubIssueError(f"Invalid GitHub repository slug: {repo!r} (expected owner/repo).")
    owner, name = parts
    if not _OWNER_RE.fullmatch(owner):
        raise GitHubIssueError(f"Invalid GitHub repository owner: {owner!r}.")
    if name in {".", ".."} or not _REPO_NAME_RE.fullmatch(name):
        raise GitHubIssueError(f"Invalid GitHub repository name: {name!r}.")
    return owner, name


def build_issue_marker(advisory_id: str) -> str:
    """Build the deterministic HTML comment marker used for issue deduplication.

    Args:
        advisory_id: Advisory identifier (e.g. ``PRECVE-2026-AA11BB22``).

    Returns:
        Comment marker ``<!-- zerobom:advisory-id:<id> -->``.

    Raises:
        GitHubIssueError: If ``advisory_id`` contains unsupported or unsafe characters.
    """
    cleaned = _validate_safe_text(advisory_id, field_name="advisory_id").strip()
    if not _SAFE_ADVISORY_ID_RE.fullmatch(cleaned):
        raise GitHubIssueError(
            f"Advisory ID {advisory_id!r} contains disallowed characters for issue marker."
        )
    return f"<!-- zerobom:advisory-id:{cleaned} -->"


def sanitize_github_markdown(text: str, *, max_length: int = 2000) -> str:
    """Sanitize untrusted text before embedding it into GitHub Flavored Markdown.

    Defends against raw HTML/XSS injection, HTML comment breakouts, automatic image
    rendering (``![alt](url)`` pixel/SSRF vectors), and unintended mass ``@mention`` pings.

    Args:
        text: Untrusted text extracted from security blogs, SBOMs, or package metadata.
        max_length: Maximum output character length before truncation.

    Returns:
        Escaped, length-bounded Markdown-safe string.
    """
    cleaned = _CONTROL_CHARS_RE.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    # Neutralize HTML/comment tags first so attacker text cannot break comment markers or XSS.
    cleaned = cleaned.replace("<!--", "&lt;!--").replace("-->", "--&gt;")
    cleaned = cleaned.replace("<", "&lt;").replace(">", "&gt;")
    # Break Markdown image auto-fetch syntax (`![` -> `!\[`).
    cleaned = cleaned.replace("![", "!\\[")
    # Break `@mention` notifications without introducing raw backtick imbalance.
    cleaned = _MENTION_RE.sub("@\u200b\\1", cleaned)
    cleaned = cleaned.strip()
    if len(cleaned) > max_length:
        cutoff = max(0, max_length - 3)
        cleaned = f"{cleaned[:cutoff]}..."
    return cleaned


def sanitize_table_cell(text: str, *, max_length: int = 200) -> str:
    """Sanitize untrusted text for safe single-line rendering inside a GFM table cell.

    Args:
        text: Untrusted cell string.
        max_length: Maximum cell length.

    Returns:
        Single-line, pipe-escaped Markdown cell string.
    """
    single_line = _WHITESPACE_RUN_RE.sub(" ", text).strip()
    sanitized = sanitize_github_markdown(single_line, max_length=max_length)
    return sanitized.replace("|", "&#124;")


def _sanitize_plain_title(text: str, *, max_length: int = 240) -> str:
    """Collapse control characters and newlines for plain-text GitHub issue titles."""
    cleaned = _CONTROL_CHARS_RE.sub("", text)
    cleaned = _WHITESPACE_RUN_RE.sub(" ", cleaned).strip()
    if len(cleaned) > max_length:
        cutoff = max(0, max_length - 3)
        return f"{cleaned[:cutoff]}..."
    return cleaned


def _format_package_summary(affected: Sequence[OsvAffected]) -> str:
    """Summarize affected package names cleanly for GitHub issue titles."""
    names: list[str] = []
    seen: set[str] = set()
    for item in affected:
        label = item.package.purl or item.package.name
        if label and label not in seen:
            seen.add(label)
            names.append(label)
    if not names:
        return "affected package"
    if len(names) <= 2:
        return ", ".join(names)
    return f"{names[0]}, {names[1]} (+{len(names) - 2} more)"


def _format_safe_source_markdown(outcome: PipelineOutcome) -> str:
    """Format validated HTTP(S) source link safely, escaping parentheses in target URL."""
    safe_url = extract_safe_source_url(outcome)
    if safe_url is None:
        return "(none)"
    escaped_url = (
        safe_url.replace("(", "%28")
        .replace(")", "%29")
        .replace(" ", "%20")
        .replace("<", "%3C")
        .replace(">", "%3E")
    )
    label = (
        sanitize_github_markdown(outcome.article.title, max_length=160)
        if outcome.article is not None and outcome.article.title.strip()
        else safe_url
    )
    label = label.replace("[", "\\[").replace("]", "\\]")
    return f"[{label}]({escaped_url})"


def _truncate_body_preserving_marker(body: str, marker: str, max_chars: int) -> str:
    """Truncate oversized Markdown body while ensuring the deduplication marker stays intact."""
    if len(body) <= max_chars:
        return body
    suffix = f"\n\n... _(truncated for GitHub issue size limit)_\n\n{marker}"
    budget = max(0, max_chars - len(suffix))
    return f"{body[:budget].rstrip()}{suffix}"


def render_github_issue(
    outcome: PipelineOutcome,
    *,
    labels: Sequence[str] = DEFAULT_ISSUE_LABELS,
    include_triage: bool = False,
) -> RenderedGitHubIssue | None:
    """Render an actionable :class:`PipelineOutcome` into a sanitized GitHub issue payload.

    Noise suppression matches ``zerobom`` alerting invariants:

    - ``DROP`` advisories and ``AUTO`` advisories with zero vulnerable matches return ``None``.
    - ``AUTO`` advisories with vulnerable inventory hits always render.
    - ``TRIAGE`` advisories render only when ``include_triage=True``.

    Args:
        outcome: Evaluated pipeline outcome.
        labels: Issue labels attached on creation.
        include_triage: When ``True``, also render pending ``TRIAGE`` review issues.

    Returns:
        Rendered issue payload, or ``None`` if no issue should be created/updated.

    Raises:
        GitHubIssueError: If an actionable outcome lacks an OSV advisory or valid labels.
    """
    event_type = classify_alert_event(outcome)
    if event_type is None:
        return None
    if event_type == "triage_review" and not include_triage:
        return None
    if outcome.osv is None:
        raise GitHubIssueError("Actionable outcome cannot render a GitHub issue without OSV data.")

    advisory = outcome.osv
    marker = build_issue_marker(advisory.id)
    pkg_summary = _sanitize_plain_title(_format_package_summary(advisory.affected), max_length=120)
    vulnerable = outcome.vulnerable_matches

    if event_type == "auto_hit":
        match_word = "vulnerable match" if len(vulnerable) == 1 else "vulnerable matches"
        raw_title = f"[zerobom] {advisory.id}: {pkg_summary} ({len(vulnerable)} {match_word})"
        status_heading = "Pre-CVE Vulnerability Hit Detected (Auto-Verified)"
    else:
        raw_title = f"[zerobom][TRIAGE] {advisory.id}: {pkg_summary} (review required)"
        status_heading = "Pre-CVE Advisory Pending Human Triage"

    title = _sanitize_plain_title(raw_title, max_length=240)
    clean_labels = _normalize_labels(labels)

    lines: list[str] = [f"## {status_heading}", ""]
    lines.append(f"- **Advisory ID:** `{advisory.id}`")
    if advisory.aliases:
        alias_list = ", ".join(sanitize_github_markdown(a, max_length=64) for a in advisory.aliases)
        lines.append(f"- **Aliases:** {alias_list}")
    if outcome.credibility is not None:
        cred = outcome.credibility
        tier = cred.source_tier.value
        zb_meta = advisory.database_specific.get("zerobom")
        fallback_source = (
            str(zb_meta.get("source_name"))
            if isinstance(zb_meta, dict) and zb_meta.get("source_name")
            else "unknown"
        )
        raw_source = outcome.article.source_name if outcome.article is not None else fallback_source
        source_name = sanitize_github_markdown(raw_source, max_length=100)
        lines.append(
            f"- **Credibility Score:** `{cred.composite_score:.4f}` "
            f"(`{cred.routing.value.upper()}` | source: {source_name} `{tier}`)"
        )
    lines.append(f"- **Source Reference:** {_format_safe_source_markdown(outcome)}")
    summary_text = advisory.summary.strip() or (
        outcome.article.title if outcome.article is not None else ""
    )
    if summary_text:
        lines.append(f"- **Summary:** {sanitize_github_markdown(summary_text, max_length=500)}")

    quotes = extract_verified_quotes(outcome)
    if quotes:
        lines.extend(["", "### Verified Evidence Quotes", ""])
        for quote in quotes:
            safe_quote = sanitize_github_markdown(quote, max_length=1000)
            for q_line in safe_quote.splitlines() or [safe_quote]:
                lines.append(f"> {q_line}")
            lines.append("")

    if advisory.affected:
        lines.extend(["### Affected Packages & Deterministic Ranges", ""])
        for affected in advisory.affected:
            pkg_label = sanitize_github_markdown(
                affected.package.purl or affected.package.name,
                max_length=180,
            )
            range_str = _format_affected_ranges(affected)
            range_suffix = (
                f" (`{sanitize_github_markdown(range_str, max_length=160)}`)" if range_str else ""
            )
            lines.append(f"- `{pkg_label}`{range_suffix}")

    if vulnerable:
        lines.extend(
            [
                "",
                "### Matched Vulnerable Inventory",
                "",
                "| Matched PURL | Installed | Fixed In | Match Path | Asset / SBOM |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for match in vulnerable[:MAX_RENDERED_MATCHES]:
            fixed = ", ".join(match.fixed_versions) if match.fixed_versions else "-"
            asset_loc = match.sbom_source or (
                match.asset.asset_id if match.asset is not None else "-"
            )
            lines.append(
                f"| `{sanitize_table_cell(match.matched_purl)}` "
                f"| `{sanitize_table_cell(match.installed_version)}` "
                f"| `{sanitize_table_cell(fixed)}` "
                f"| {sanitize_table_cell(match.matched_via)} "
                f"| {sanitize_table_cell(asset_loc)} |"
            )
        if len(vulnerable) > MAX_RENDERED_MATCHES:
            remaining = len(vulnerable) - MAX_RENDERED_MATCHES
            lines.append(f"\n_... and {remaining} additional vulnerable matches omitted._")

    if event_type == "triage_review":
        lines.extend(
            [
                "",
                "### Required Action",
                "",
                "Verify the quoted evidence above against the source article, then run:",
                "",
                f"    zerobom triage approve {advisory.id}",
            ]
        )

    lines.extend(["", marker])
    body = _truncate_body_preserving_marker("\n".join(lines), marker, MAX_ISSUE_BODY_CHARS)

    return RenderedGitHubIssue(
        advisory_id=advisory.id,
        event_type=event_type,
        marker=marker,
        title=title,
        body=body,
        labels=clean_labels,
    )


class GitHubIssueSyncer:
    """Idempotent GitHub REST API v3 client for creating and updating ``zerobom`` issues.

    Deduplicates issues across repeated CI runs using the hidden HTML marker
    ``<!-- zerobom:advisory-id:<id> -->`` rather than brittle issue titles.
    """

    def __init__(
        self,
        repo: str,
        token: str,
        *,
        api_base_url: str = DEFAULT_GITHUB_API_URL,
        labels: Sequence[str] = DEFAULT_ISSUE_LABELS,
        include_triage: bool = False,
        dry_run: bool = False,
        timeout_seconds: float = 15.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        """Initialize a GitHub issue syncer targeting a single repository.

        Args:
            repo: Target repository in ``owner/name`` format.
            token: GitHub bearer credential with ``issues: write`` scope.
            api_base_url: GitHub REST API base URL (HTTPS enforced).
            labels: Labels attached when creating new issues.
            include_triage: Also sync issues for pending ``TRIAGE`` review items.
            dry_run: Compute create/update decisions without mutating GitHub state.
            timeout_seconds: Bounded per-request timeout in seconds.
            http_client: Optional injected ``httpx.Client`` for unit testing.

        Raises:
            GitHubIssueError: If ``repo``, ``token``, or ``api_base_url`` is invalid.
        """
        self._owner, self._name = validate_github_repo(repo)
        self._repo = f"{self._owner}/{self._name}"
        cleaned_cred = _validate_safe_text(token, field_name="github_token").strip()
        if not cleaned_cred:
            raise GitHubIssueError("GitHub token must not be empty.")
        self._cred = cleaned_cred

        try:
            self._api_base_url = validate_api_base_url(
                api_base_url,
                allow_insecure_http=False,
                field_name="github_api_url",
                allow_query=False,
            )
            self._timeout_seconds = validate_timeout_seconds(timeout_seconds)
        except (BackendError, ValueError) as exc:
            raise GitHubIssueError(str(exc)) from exc

        self._labels = _normalize_labels(labels)
        self._include_triage = bool(include_triage)
        self._dry_run = bool(dry_run)
        self._owns_client = http_client is None
        self._client = (
            http_client
            if http_client is not None
            else httpx.Client(
                timeout=httpx.Timeout(self._timeout_seconds),
                follow_redirects=False,
            )
        )
        # Cached open issues indexed by marker; populated lazily on first actionable issue.
        self._open_issues_by_marker: dict[str, tuple[int, str, str, str]] | None = None

    def __repr__(self) -> str:
        """Return diagnostic string with credentials redacted."""
        return (
            f"GitHubIssueSyncer(repo={self._repo!r}, "
            f"api_base_url={self._api_base_url!r}, dry_run={self._dry_run})"
        )

    def __enter__(self) -> GitHubIssueSyncer:
        """Enter context manager."""
        return self

    def __exit__(self, *_args: object) -> None:
        """Close owned HTTP resources."""
        self.close()

    def close(self) -> None:
        """Close the underlying ``httpx.Client`` if owned by this instance."""
        if self._owns_client:
            self._client.close()

    def _headers(self) -> dict[str, str]:
        """Return standard GitHub REST v3 request headers."""
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._cred}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": DEFAULT_USER_AGENT,
        }

    def _issues_url(self) -> str:
        """Build validated REST issues collection endpoint URL."""
        return f"{self._api_base_url}/repos/{self._owner}/{self._name}/issues"

    def _request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: Any | None = None,
    ) -> tuple[int, Any]:
        """Execute a bounded, non-redirecting GitHub REST call and decode JSON."""
        try:
            status, _headers, raw_body = read_bounded_response(
                self._client,
                method,
                url,
                max_bytes=MAX_GITHUB_RESPONSE_BYTES,
                params=params,
                headers=self._headers(),
                json_body=json_body,
                backend_name="github_issue",
            )
        except (BackendError, httpx.HTTPError) as exc:
            raise GitHubIssueError(f"GitHub API request failed: {exc}") from exc

        if status in REDIRECT_STATUS_CODES:
            raise GitHubIssueError(f"GitHub API rejected unexpected HTTP redirect status {status}.")
        if status >= 400:
            raise GitHubIssueError(
                f"GitHub API returned error HTTP {status} for {method} {self._repo}."
            )

        try:
            parsed = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise GitHubIssueError(f"GitHub API returned invalid JSON payload: {exc}") from exc
        return status, parsed

    def _ensure_open_issues(self) -> dict[str, tuple[int, str, str, str]]:
        """Fetch and index open ``zerobom`` issues by deduplication comment marker."""
        if self._open_issues_by_marker is not None:
            return self._open_issues_by_marker

        indexed: dict[str, tuple[int, str, str, str]] = {}
        primary_label = self._labels[0]
        collection_url = self._issues_url()
        completed = False

        for page in range(1, MAX_OPEN_ISSUE_PAGES + 1):
            _status, payload = self._request_json(
                "GET",
                collection_url,
                params={
                    "state": "open",
                    "labels": primary_label,
                    "per_page": 100,
                    "page": page,
                },
            )
            if not isinstance(payload, list):
                raise GitHubIssueError("GitHub issues listing response was not a JSON array.")

            for item in payload:
                if not isinstance(item, dict) or "pull_request" in item:
                    continue
                number = item.get("number")
                if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
                    continue
                body = item.get("body")
                body_str = body if isinstance(body, str) else ""
                match = _MARKER_RE.search(body_str)
                if match is None:
                    continue
                marker = f"<!-- zerobom:advisory-id:{match.group(1)} -->"
                if marker in indexed:
                    continue
                title_val = item.get("title")
                html_url_val = item.get("html_url")
                indexed[marker] = (
                    number,
                    html_url_val if isinstance(html_url_val, str) else "",
                    title_val if isinstance(title_val, str) else "",
                    body_str,
                )

            if len(payload) < 100:
                completed = True
                break

        if not completed:
            raise GitHubIssueError(
                f"GitHub open issues pagination exceeded {MAX_OPEN_ISSUE_PAGES} pages "
                f"for {self._repo}; refusing to create potentially duplicate issues."
            )

        self._open_issues_by_marker = indexed
        return indexed

    def sync_outcome(self, outcome: PipelineOutcome) -> IssueSyncResult:
        """Create, update, or leave unchanged the GitHub issue for one pipeline outcome.

        Args:
            outcome: Evaluated :class:`PipelineOutcome` instance.

        Returns:
            Structured :class:`IssueSyncResult` describing the sync decision.

        Raises:
            GitHubIssueError: If issue rendering or GitHub API synchronization fails.
        """
        fallback_id = outcome.osv.id if outcome.osv is not None else "unknown"
        rendered = render_github_issue(
            outcome,
            labels=self._labels,
            include_triage=self._include_triage,
        )
        if rendered is None:
            return IssueSyncResult(
                advisory_id=fallback_id,
                action="skipped",
                reason="Outcome did not meet GitHub issue notification criteria.",
            )

        open_issues = self._ensure_open_issues()
        existing = open_issues.get(rendered.marker)

        if existing is None:
            if self._dry_run:
                return IssueSyncResult(advisory_id=rendered.advisory_id, action="dry_run_create")
            status, created = self._request_json(
                "POST",
                self._issues_url(),
                json_body={
                    "title": rendered.title,
                    "body": rendered.body,
                    "labels": list(rendered.labels),
                },
            )
            if status not in (200, 201) or not isinstance(created, dict):
                raise GitHubIssueError(
                    f"Unexpected GitHub issue creation response status {status}."
                )
            issue_num = created.get("number")
            html_url = created.get("html_url")
            num_int = (
                issue_num
                if isinstance(issue_num, int) and not isinstance(issue_num, bool) and issue_num > 0
                else None
            )
            url_str = html_url if isinstance(html_url, str) else None
            if num_int is not None:
                open_issues[rendered.marker] = (
                    num_int,
                    url_str or "",
                    rendered.title,
                    rendered.body,
                )
            return IssueSyncResult(
                advisory_id=rendered.advisory_id,
                action="created",
                issue_number=num_int,
                issue_url=url_str,
            )

        issue_num, issue_url, current_title, current_body = existing
        if current_title == rendered.title and current_body == rendered.body:
            return IssueSyncResult(
                advisory_id=rendered.advisory_id,
                action="unchanged",
                issue_number=issue_num,
                issue_url=issue_url or None,
            )

        if self._dry_run:
            return IssueSyncResult(
                advisory_id=rendered.advisory_id,
                action="dry_run_update",
                issue_number=issue_num,
                issue_url=issue_url or None,
            )

        patch_url = f"{self._issues_url()}/{issue_num}"
        status, updated = self._request_json(
            "PATCH",
            patch_url,
            json_body={"title": rendered.title, "body": rendered.body},
        )
        if status != 200 or not isinstance(updated, dict):
            raise GitHubIssueError(f"Unexpected GitHub issue update response status {status}.")
        updated_url = updated.get("html_url")
        final_url = updated_url if isinstance(updated_url, str) else (issue_url or None)
        open_issues[rendered.marker] = (
            issue_num,
            final_url or "",
            rendered.title,
            rendered.body,
        )
        return IssueSyncResult(
            advisory_id=rendered.advisory_id,
            action="updated",
            issue_number=issue_num,
            issue_url=final_url,
        )

    def sync_outcomes(self, outcomes: Sequence[PipelineOutcome]) -> tuple[IssueSyncResult, ...]:
        """Synchronize GitHub issues across a sequence of pipeline outcomes.

        Args:
            outcomes: Sequence of evaluated :class:`PipelineOutcome` instances.

        Returns:
            Tuple of :class:`IssueSyncResult` instances in input order.
        """
        return tuple(self.sync_outcome(outcome) for outcome in outcomes)
