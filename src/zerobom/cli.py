"""Thin Typer CLI entrypoint for ``zerobom``."""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from contextlib import ExitStack, suppress
from enum import StrEnum
from io import StringIO
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from zerobom import __version__
from zerobom.backends import (
    BackendError,
    BackendRegistry,
    InventoryBackend,
    SbomParseError,
    parse_backend_options,
)
from zerobom.extract import ExtractionError, Extractor, OpenAICompatConfig, OpenAICompatExtractor
from zerobom.ingest import FetchError, IngestStateStore, SafeHttpFetcher, load_sources_config
from zerobom.models import (
    CredibilityReport,
    OsvAdvisory,
    PipelineOutcome,
    SourceTier,
)
from zerobom.outputs import (
    DEFAULT_GITHUB_API_URL,
    AlertDeliveryError,
    GitHubIssueError,
    GitHubIssueSyncer,
    SlackNotifier,
    WebhookNotifier,
    render_json_outcomes,
    render_sarif,
    render_terminal_outcomes,
)
from zerobom.pipeline import check_url, run_offline_demo, scan_osv_files, watch_feeds
from zerobom.triage import (
    TriageActionHandler,
    TriageError,
    TriageQueueStore,
    TriageStatus,
    TriageWebhookServer,
    run_socket_mode_worker,
)
from zerobom.verify import HttpRegistryChecker, RegistryChecker

EXIT_OK = 0
EXIT_VULNERABLE = 1
EXIT_ERROR = 2


class OutputFormat(StrEnum):
    """Supported CLI output serialization formats."""

    TERMINAL = "terminal"
    JSON = "json"
    SARIF = "sarif"


class WorkerTransport(StrEnum):
    """Supported transport modes for ``zerobom triage-worker``."""

    HTTP = "http"
    SOCKET_MODE = "socket-mode"


app = typer.Typer(
    name="zerobom",
    help="Deterministic pre-CVE security advisory verification and SBOM matching CLI.",
    no_args_is_help=True,
)
triage_app = typer.Typer(
    name="triage",
    help="Inspect, approve, or reject queued TRIAGE advisories.",
    no_args_is_help=True,
)
app.add_typer(triage_app, name="triage")


def _version_callback(show_version: bool) -> None:
    """Print the installed zerobom version and exit cleanly."""
    if show_version:
        typer.echo(f"zerobom {__version__}")
        raise typer.Exit(code=EXIT_OK)


@app.callback()
def _main_callback(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show installed zerobom version and exit.",
        ),
    ] = False,
) -> None:
    """Global options for the zerobom CLI."""
    del version


def _create_fetcher() -> SafeHttpFetcher:
    """Factory hook constructing the default SSRF-hardened HTTP fetcher."""
    return SafeHttpFetcher()


def _create_extractor() -> OpenAICompatExtractor:
    """Factory hook constructing the default OpenAI-compatible extractor from env vars."""
    return OpenAICompatExtractor(OpenAICompatConfig.from_env())


def _create_registry_checker(verify_registry: bool) -> HttpRegistryChecker | None:
    """Factory hook constructing an upstream registry checker when enabled."""
    if not verify_registry:
        return None
    return HttpRegistryChecker()


def _create_backend(
    backend_name: str,
    sbom_path: Path | None,
    *,
    backend_opts: Sequence[str] = (),
    backend_config: Path | None = None,
) -> InventoryBackend | None:
    """Instantiate an inventory backend plugin by name from ``zerobom.backends``."""
    config = parse_backend_options(backend_opts, config_path=backend_config)
    if sbom_path is not None:
        config["paths"] = sbom_path

    if backend_name == "local_sbom" and not any(
        key in config and config[key] is not None for key in ("paths", "path", "sbom")
    ):
        return None

    registry = BackendRegistry()
    if config:
        return registry.create(backend_name, config=config)
    return registry.create(backend_name)


def _require_configured_backend(
    backend_name: str,
    sbom_path: Path | None,
    *,
    backend_opts: Sequence[str] = (),
    backend_config: Path | None = None,
) -> None:
    """Validate backend config and require ``--sbom`` when using ``local_sbom``."""
    config = parse_backend_options(backend_opts, config_path=backend_config)
    if sbom_path is not None:
        return
    if backend_name == "local_sbom" and not any(
        key in config and config[key] is not None for key in ("paths", "path", "sbom")
    ):
        raise ValueError("--sbom is required when using the 'local_sbom' backend.")


def _register_backend_cleanup(stack: ExitStack, backend: InventoryBackend | None) -> None:
    """Register ``backend.close()`` cleanup on ``stack`` when provided by a plugin."""
    if backend is None:
        return
    close_fn = getattr(backend, "close", None)
    if callable(close_fn):
        stack.callback(close_fn)


def _validate_output_path(output_path: Path) -> None:
    """Reject ASCII control characters in CLI output paths."""
    raw = str(output_path)
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise ValueError("Output path must not contain control characters.")


def _emit_outcomes(
    outcomes: Sequence[PipelineOutcome],
    *,
    output_format: OutputFormat,
    output_path: Path | None,
    json_out: Path | None = None,
    sarif_out: Path | None = None,
) -> None:
    """Render outcomes to stdout and/or validated multi-sink output files in a single pass."""
    for candidate in (output_path, json_out, sarif_out):
        if candidate is not None:
            _validate_output_path(candidate)

    json_text = (
        render_json_outcomes(outcomes)
        if json_out is not None or output_format == OutputFormat.JSON
        else None
    )
    sarif_text = (
        render_sarif(outcomes)
        if sarif_out is not None or output_format == OutputFormat.SARIF
        else None
    )

    if json_out is not None and json_text is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json_text, encoding="utf-8")

    if sarif_out is not None and sarif_text is not None:
        sarif_out.parent.mkdir(parents=True, exist_ok=True)
        sarif_out.write_text(sarif_text, encoding="utf-8")

    if output_format == OutputFormat.JSON and json_text is not None:
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json_text, encoding="utf-8")
        else:
            typer.echo(json_text)
        return

    if output_format == OutputFormat.SARIF and sarif_text is not None:
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(sarif_text, encoding="utf-8")
        else:
            typer.echo(sarif_text)
        return

    if output_path is not None:
        buffer = StringIO()
        console = Console(file=buffer, no_color=True, width=120)
        render_terminal_outcomes(outcomes, console=console)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(buffer.getvalue(), encoding="utf-8")
    else:
        render_terminal_outcomes(outcomes)


def _exit_code_for_outcomes(
    outcomes: Sequence[PipelineOutcome],
    *,
    fail_on_hits: bool,
) -> int:
    """Determine deterministic CI exit code from pipeline outcomes."""
    if fail_on_hits and any(outcome.has_vulnerable_hits for outcome in outcomes):
        return EXIT_VULNERABLE
    return EXIT_OK


def _build_alert_notifiers(
    stack: ExitStack,
    *,
    webhook_url: str | None,
    webhook_secret: str | None,
    slack_webhook_url: str | None,
    allow_private_webhook: bool,
) -> tuple[WebhookNotifier | SlackNotifier, ...]:
    """Instantiate configured webhook and Slack notifiers and register cleanup."""
    resolved_wh_url = webhook_url or os.environ.get("ZEROBOM_WEBHOOK_URL") or None
    resolved_wh_secret = webhook_secret or os.environ.get("ZEROBOM_WEBHOOK_SECRET") or None
    resolved_slack_url = slack_webhook_url or os.environ.get("ZEROBOM_SLACK_WEBHOOK_URL") or None

    notifiers: list[WebhookNotifier | SlackNotifier] = []
    if resolved_wh_url and resolved_wh_url.strip():
        wh_notifier = WebhookNotifier(
            resolved_wh_url,
            signing_secret=resolved_wh_secret,
            allow_private_targets=allow_private_webhook,
        )
        stack.enter_context(wh_notifier)
        notifiers.append(wh_notifier)
    if resolved_slack_url and resolved_slack_url.strip():
        slack_notifier = SlackNotifier(resolved_slack_url)
        stack.enter_context(slack_notifier)
        notifiers.append(slack_notifier)
    return tuple(notifiers)


def _create_github_syncer(
    repo: str,
    token: str,
    *,
    api_base_url: str,
    include_triage: bool,
) -> GitHubIssueSyncer:
    """Factory hook constructing the GitHub REST issue synchronizer."""
    return GitHubIssueSyncer(
        repo,
        token,
        api_base_url=api_base_url,
        include_triage=include_triage,
    )


def _dispatch_alerts_and_triage(
    outcomes: Sequence[PipelineOutcome],
    *,
    triage_db: Path | None,
    webhook_url: str | None,
    webhook_secret: str | None,
    slack_webhook_url: str | None,
    allow_private_webhook: bool,
    github_repo: str | None = None,
    github_token: str | None = None,
    github_api_url: str | None = None,
    github_issue_triage: bool = False,
) -> None:
    """Enqueue TRIAGE advisories when enabled and deliver deduplicated outbound alerts."""
    store = TriageQueueStore(triage_db) if triage_db is not None else None
    triage_ids: dict[str, str] = {}
    if store is not None:
        for outcome in outcomes:
            record = store.enqueue_outcome(outcome)
            if record is not None:
                triage_ids[record.advisory_id] = record.triage_id

    resolved_gh_repo = (github_repo or os.environ.get("ZEROBOM_GITHUB_REPO") or "").strip() or None
    resolved_gh_token = (
        github_token
        or os.environ.get("ZEROBOM_GITHUB_TOKEN")
        or os.environ.get("GITHUB_TOKEN")
        or None
    )
    resolved_gh_api = (
        github_api_url or os.environ.get("ZEROBOM_GITHUB_API_URL") or DEFAULT_GITHUB_API_URL
    )

    with ExitStack() as stack:
        notifiers = _build_alert_notifiers(
            stack,
            webhook_url=webhook_url,
            webhook_secret=webhook_secret,
            slack_webhook_url=slack_webhook_url,
            allow_private_webhook=allow_private_webhook,
        )
        for notifier in notifiers:
            channel = "slack" if isinstance(notifier, SlackNotifier) else "webhook"
            dedup_fn = (
                (lambda tid, dig, s=store, ch=channel: s.should_notify(tid, dig, channel=ch))
                if store is not None
                else None
            )
            mark_fn = (
                (lambda tid, dig, s=store, ch=channel: s.mark_notified(tid, dig, channel=ch))
                if store is not None
                else None
            )
            notifier.send_outcomes(
                outcomes,
                triage_ids=triage_ids,
                dedup_check=dedup_fn,
                on_sent=mark_fn,
            )

        if resolved_gh_repo is not None:
            if not resolved_gh_token or not resolved_gh_token.strip():
                raise GitHubIssueError(
                    "GitHub token is required when --github-repo is set "
                    "(pass --github-token or set ZEROBOM_GITHUB_TOKEN / GITHUB_TOKEN)."
                )
            syncer = _create_github_syncer(
                resolved_gh_repo,
                resolved_gh_token,
                api_base_url=resolved_gh_api,
                include_triage=github_issue_triage,
            )
            stack.enter_context(syncer)
            syncer.sync_outcomes(outcomes)


@app.command()
def demo(
    format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Output format: terminal, json, or sarif."),
    ] = OutputFormat.TERMINAL,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Optional path to write rendered output."),
    ] = None,
    json_out: Annotated[
        Path | None,
        typer.Option("--json-out", help="Optional path to write JSON output alongside --format."),
    ] = None,
    sarif_out: Annotated[
        Path | None,
        typer.Option("--sarif-out", help="Optional path to write SARIF output alongside --format."),
    ] = None,
) -> None:
    """Run an offline end-to-end demonstration using bundled pre-CVE and SBOM fixtures."""
    try:
        outcome = run_offline_demo()
        _emit_outcomes(
            (outcome,),
            output_format=format,
            output_path=output,
            json_out=json_out,
            sarif_out=sarif_out,
        )
    except (ValueError, SbomParseError) as exc:
        typer.echo(f"Error running demo: {exc}", err=True)
        raise typer.Exit(code=EXIT_ERROR) from exc
    raise typer.Exit(code=EXIT_OK)


@app.command()
def scan(
    osv: Annotated[
        Path,
        typer.Option("--osv", help="Path to an OSV JSON file or directory of OSV JSON files."),
    ],
    sbom: Annotated[
        Path | None,
        typer.Option("--sbom", help="Path to CycloneDX/SPDX JSON file or directory."),
    ] = None,
    backend: Annotated[
        str,
        typer.Option("--backend", help="Registered inventory backend plugin name."),
    ] = "local_sbom",
    backend_opt: Annotated[
        list[str] | None,
        typer.Option(
            "--backend-opt",
            help="Repeatable KEY=VALUE configuration option passed to the inventory backend.",
        ),
    ] = None,
    backend_config: Annotated[
        Path | None,
        typer.Option(
            "--backend-config",
            help="Optional YAML/JSON configuration file for the inventory backend.",
        ),
    ] = None,
    webhook_url: Annotated[
        str | None,
        typer.Option("--webhook-url", help="Optional generic HTTPS webhook alert URL."),
    ] = None,
    webhook_secret: Annotated[
        str | None,
        typer.Option("--webhook-secret", help="Optional HMAC-SHA256 webhook signing secret."),
    ] = None,
    slack_webhook_url: Annotated[
        str | None,
        typer.Option("--slack-webhook-url", help="Optional Slack Incoming Webhook URL."),
    ] = None,
    allow_private_webhook: Annotated[
        bool,
        typer.Option(
            "--allow-private-webhook",
            help="Permit webhook delivery to private/loopback endpoints (internal relays only).",
        ),
    ] = False,
    github_repo: Annotated[
        str | None,
        typer.Option("--github-repo", help="Optional GitHub owner/repo for idempotent issue sync."),
    ] = None,
    github_token: Annotated[
        str | None,
        typer.Option(
            "--github-token", help="GitHub token (or GITHUB_TOKEN / ZEROBOM_GITHUB_TOKEN)."
        ),
    ] = None,
    github_api_url: Annotated[
        str | None,
        typer.Option("--github-api-url", help="Optional GitHub Enterprise REST API base URL."),
    ] = None,
    github_issue_triage: Annotated[
        bool,
        typer.Option(
            "--github-issue-triage",
            help="Also open GitHub review issues for pending TRIAGE advisories.",
        ),
    ] = False,
    format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Output format: terminal, json, or sarif."),
    ] = OutputFormat.TERMINAL,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Optional path to write rendered output."),
    ] = None,
    json_out: Annotated[
        Path | None,
        typer.Option("--json-out", help="Optional path to write JSON output alongside --format."),
    ] = None,
    sarif_out: Annotated[
        Path | None,
        typer.Option("--sarif-out", help="Optional path to write SARIF output alongside --format."),
    ] = None,
    fail_on_hits: Annotated[
        bool,
        typer.Option(
            "--fail-on-hits/--no-fail-on-hits",
            help="Exit with code 1 when vulnerable inventory hits are detected.",
        ),
    ] = True,
) -> None:
    """Deterministically scan an inventory against OSV JSON advisories with zero LLM calls."""
    try:
        with ExitStack() as stack:
            inv_backend = _create_backend(
                backend,
                sbom,
                backend_opts=backend_opt or (),
                backend_config=backend_config,
            )
            if inv_backend is None:
                raise ValueError("--sbom is required when using the 'local_sbom' backend.")
            _register_backend_cleanup(stack, inv_backend)
            outcomes = scan_osv_files(osv, backend=inv_backend)
        _dispatch_alerts_and_triage(
            outcomes,
            triage_db=None,
            webhook_url=webhook_url,
            webhook_secret=webhook_secret,
            slack_webhook_url=slack_webhook_url,
            allow_private_webhook=allow_private_webhook,
            github_repo=github_repo,
            github_token=github_token,
            github_api_url=github_api_url,
            github_issue_triage=github_issue_triage,
        )
        _emit_outcomes(
            outcomes,
            output_format=format,
            output_path=output,
            json_out=json_out,
            sarif_out=sarif_out,
        )
    except (ValueError, SbomParseError, BackendError, AlertDeliveryError, TriageError) as exc:
        typer.echo(f"Scan error: {exc}", err=True)
        raise typer.Exit(code=EXIT_ERROR) from exc

    raise typer.Exit(code=_exit_code_for_outcomes(outcomes, fail_on_hits=fail_on_hits))


@app.command()
def check(
    url: Annotated[
        str,
        typer.Option("--url", help="Security blog or advisory URL to fetch and verify."),
    ],
    sbom: Annotated[
        Path | None,
        typer.Option("--sbom", help="Path to CycloneDX/SPDX JSON file or directory."),
    ] = None,
    backend: Annotated[
        str,
        typer.Option("--backend", help="Registered inventory backend plugin name."),
    ] = "local_sbom",
    backend_opt: Annotated[
        list[str] | None,
        typer.Option(
            "--backend-opt",
            help="Repeatable KEY=VALUE configuration option passed to the inventory backend.",
        ),
    ] = None,
    backend_config: Annotated[
        Path | None,
        typer.Option(
            "--backend-config",
            help="Optional YAML/JSON configuration file for the inventory backend.",
        ),
    ] = None,
    tier: Annotated[
        SourceTier,
        typer.Option("--tier", help="Source credibility tier: tier_1, tier_2, or unknown."),
    ] = SourceTier.UNKNOWN,
    source_name: Annotated[
        str,
        typer.Option("--source-name", help="Human-readable publisher name."),
    ] = "Manual URL",
    verify_registry: Annotated[
        bool,
        typer.Option(
            "--verify-registry/--no-verify-registry",
            help="Verify extracted package existence against upstream registries.",
        ),
    ] = False,
    include_triage: Annotated[
        bool,
        typer.Option("--include-triage", help="Also query inventory for TRIAGE advisories."),
    ] = False,
    skip_prefilter: Annotated[
        bool,
        typer.Option("--skip-prefilter", help="Bypass the pre-LLM keyword/regex filter."),
    ] = False,
    triage_db: Annotated[
        Path | None,
        typer.Option("--triage-db", help="Optional SQLite DB path to persist TRIAGE items."),
    ] = None,
    webhook_url: Annotated[
        str | None,
        typer.Option("--webhook-url", help="Optional generic HTTPS webhook alert URL."),
    ] = None,
    webhook_secret: Annotated[
        str | None,
        typer.Option("--webhook-secret", help="Optional HMAC-SHA256 webhook signing secret."),
    ] = None,
    slack_webhook_url: Annotated[
        str | None,
        typer.Option("--slack-webhook-url", help="Optional Slack Incoming Webhook URL."),
    ] = None,
    allow_private_webhook: Annotated[
        bool,
        typer.Option(
            "--allow-private-webhook",
            help="Permit webhook delivery to private/loopback endpoints (internal relays only).",
        ),
    ] = False,
    github_repo: Annotated[
        str | None,
        typer.Option("--github-repo", help="Optional GitHub owner/repo for idempotent issue sync."),
    ] = None,
    github_token: Annotated[
        str | None,
        typer.Option(
            "--github-token", help="GitHub token (or GITHUB_TOKEN / ZEROBOM_GITHUB_TOKEN)."
        ),
    ] = None,
    github_api_url: Annotated[
        str | None,
        typer.Option("--github-api-url", help="Optional GitHub Enterprise REST API base URL."),
    ] = None,
    github_issue_triage: Annotated[
        bool,
        typer.Option(
            "--github-issue-triage",
            help="Also open GitHub review issues for pending TRIAGE advisories.",
        ),
    ] = False,
    format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Output format: terminal, json, or sarif."),
    ] = OutputFormat.TERMINAL,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Optional path to write rendered output."),
    ] = None,
    json_out: Annotated[
        Path | None,
        typer.Option("--json-out", help="Optional path to write JSON output alongside --format."),
    ] = None,
    sarif_out: Annotated[
        Path | None,
        typer.Option("--sarif-out", help="Optional path to write SARIF output alongside --format."),
    ] = None,
    fail_on_hits: Annotated[
        bool,
        typer.Option(
            "--fail-on-hits/--no-fail-on-hits",
            help="Exit with code 1 when vulnerable inventory hits are detected.",
        ),
    ] = True,
) -> None:
    """Fetch a single advisory URL, verify claims deterministically, and match inventory."""
    try:
        with ExitStack() as stack:
            inv_backend = _create_backend(
                backend,
                sbom,
                backend_opts=backend_opt or (),
                backend_config=backend_config,
            )
            _register_backend_cleanup(stack, inv_backend)
            fetcher = stack.enter_context(_create_fetcher())
            extractor: Extractor = stack.enter_context(_create_extractor())
            checker: RegistryChecker | None = None
            raw_checker = _create_registry_checker(verify_registry)
            if raw_checker is not None:
                checker = stack.enter_context(raw_checker)

            outcome = check_url(
                url,
                fetcher=fetcher,
                extractor=extractor,
                backend=inv_backend,
                source_name=source_name,
                source_tier=tier,
                registry_checker=checker,
                run_prefilter=not skip_prefilter,
                query_on_triage=include_triage,
            )
        _dispatch_alerts_and_triage(
            (outcome,),
            triage_db=triage_db,
            webhook_url=webhook_url,
            webhook_secret=webhook_secret,
            slack_webhook_url=slack_webhook_url,
            allow_private_webhook=allow_private_webhook,
            github_repo=github_repo,
            github_token=github_token,
            github_api_url=github_api_url,
            github_issue_triage=github_issue_triage,
        )
        _emit_outcomes(
            (outcome,),
            output_format=format,
            output_path=output,
            json_out=json_out,
            sarif_out=sarif_out,
        )
    except (
        FetchError,
        ExtractionError,
        SbomParseError,
        BackendError,
        AlertDeliveryError,
        TriageError,
        ValueError,
    ) as exc:
        typer.echo(f"Check error: {exc}", err=True)
        raise typer.Exit(code=EXIT_ERROR) from exc

    raise typer.Exit(code=_exit_code_for_outcomes((outcome,), fail_on_hits=fail_on_hits))


@app.command()
def watch(
    feeds: Annotated[
        Path,
        typer.Option("--feeds", help="Path to sources.yaml RSS/Atom allowlist."),
    ] = Path("sources.yaml"),
    sbom: Annotated[
        Path | None,
        typer.Option("--sbom", help="Path to CycloneDX/SPDX JSON file or directory."),
    ] = None,
    sbom_dir: Annotated[
        Path | None,
        typer.Option(
            "--sbom-dir",
            help="Legacy alias for --sbom (CycloneDX/SPDX SBOM file or directory).",
        ),
    ] = None,
    backend: Annotated[
        str,
        typer.Option("--backend", help="Registered inventory backend plugin name."),
    ] = "local_sbom",
    backend_opt: Annotated[
        list[str] | None,
        typer.Option(
            "--backend-opt",
            help="Repeatable KEY=VALUE configuration option passed to the inventory backend.",
        ),
    ] = None,
    backend_config: Annotated[
        Path | None,
        typer.Option(
            "--backend-config",
            help="Optional YAML/JSON configuration file for the inventory backend.",
        ),
    ] = None,
    state_db: Annotated[
        Path | None,
        typer.Option("--state-db", help="Optional SQLite state DB for conditional polling."),
    ] = None,
    verify_registry: Annotated[
        bool,
        typer.Option(
            "--verify-registry/--no-verify-registry",
            help="Verify extracted package existence against upstream registries.",
        ),
    ] = False,
    include_triage: Annotated[
        bool,
        typer.Option("--include-triage", help="Also query inventory for TRIAGE advisories."),
    ] = False,
    triage_db: Annotated[
        Path | None,
        typer.Option("--triage-db", help="Optional SQLite DB path to persist TRIAGE items."),
    ] = None,
    webhook_url: Annotated[
        str | None,
        typer.Option("--webhook-url", help="Optional generic HTTPS webhook alert URL."),
    ] = None,
    webhook_secret: Annotated[
        str | None,
        typer.Option("--webhook-secret", help="Optional HMAC-SHA256 webhook signing secret."),
    ] = None,
    slack_webhook_url: Annotated[
        str | None,
        typer.Option("--slack-webhook-url", help="Optional Slack Incoming Webhook URL."),
    ] = None,
    allow_private_webhook: Annotated[
        bool,
        typer.Option(
            "--allow-private-webhook",
            help="Permit webhook delivery to private/loopback endpoints (internal relays only).",
        ),
    ] = False,
    github_repo: Annotated[
        str | None,
        typer.Option("--github-repo", help="Optional GitHub owner/repo for idempotent issue sync."),
    ] = None,
    github_token: Annotated[
        str | None,
        typer.Option(
            "--github-token", help="GitHub token (or GITHUB_TOKEN / ZEROBOM_GITHUB_TOKEN)."
        ),
    ] = None,
    github_api_url: Annotated[
        str | None,
        typer.Option("--github-api-url", help="Optional GitHub Enterprise REST API base URL."),
    ] = None,
    github_issue_triage: Annotated[
        bool,
        typer.Option(
            "--github-issue-triage",
            help="Also open GitHub review issues for pending TRIAGE advisories.",
        ),
    ] = False,
    format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Output format: terminal, json, or sarif."),
    ] = OutputFormat.TERMINAL,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Optional path to write rendered output."),
    ] = None,
    json_out: Annotated[
        Path | None,
        typer.Option("--json-out", help="Optional path to write JSON output alongside --format."),
    ] = None,
    sarif_out: Annotated[
        Path | None,
        typer.Option("--sarif-out", help="Optional path to write SARIF output alongside --format."),
    ] = None,
    fail_on_hits: Annotated[
        bool,
        typer.Option(
            "--fail-on-hits/--no-fail-on-hits",
            help="Exit with code 1 when vulnerable inventory hits are detected.",
        ),
    ] = True,
) -> None:
    """Poll configured security blog feeds for new or edited advisories and match inventory."""
    try:
        if sbom is not None and sbom_dir is not None:
            raise ValueError("Pass either --sbom or --sbom-dir, not both.")
        resolved_sbom = sbom if sbom is not None else sbom_dir

        sources_cfg = load_sources_config(feeds)
        store = IngestStateStore(state_db) if state_db is not None else None

        with ExitStack() as stack:
            inv_backend = _create_backend(
                backend,
                resolved_sbom,
                backend_opts=backend_opt or (),
                backend_config=backend_config,
            )
            _register_backend_cleanup(stack, inv_backend)
            fetcher = stack.enter_context(_create_fetcher())
            extractor: Extractor = stack.enter_context(_create_extractor())
            checker: RegistryChecker | None = None
            raw_checker = _create_registry_checker(verify_registry)
            if raw_checker is not None:
                checker = stack.enter_context(raw_checker)

            outcomes = watch_feeds(
                sources_cfg.feeds,
                fetcher=fetcher,
                extractor=extractor,
                backend=inv_backend,
                state_store=store,
                registry_checker=checker,
                query_on_triage=include_triage,
            )
        _dispatch_alerts_and_triage(
            outcomes,
            triage_db=triage_db,
            webhook_url=webhook_url,
            webhook_secret=webhook_secret,
            slack_webhook_url=slack_webhook_url,
            allow_private_webhook=allow_private_webhook,
            github_repo=github_repo,
            github_token=github_token,
            github_api_url=github_api_url,
            github_issue_triage=github_issue_triage,
        )
        _emit_outcomes(
            outcomes,
            output_format=format,
            output_path=output,
            json_out=json_out,
            sarif_out=sarif_out,
        )
    except (
        FetchError,
        ExtractionError,
        SbomParseError,
        BackendError,
        AlertDeliveryError,
        TriageError,
        ValueError,
    ) as exc:
        typer.echo(f"Watch error: {exc}", err=True)
        raise typer.Exit(code=EXIT_ERROR) from exc

    raise typer.Exit(code=_exit_code_for_outcomes(outcomes, fail_on_hits=fail_on_hits))


@app.command()
def backends() -> None:
    """List discovered ``zerobom.backends`` inventory plugins."""
    for name in BackendRegistry().list_backends():
        typer.echo(name)
    raise typer.Exit(code=EXIT_OK)


def _format_triage_record(record: Any) -> dict[str, Any]:
    """Convert a ``TriageRecord`` into a safe JSON-serializable summary dict."""
    return {
        "triage_id": record.triage_id,
        "advisory_id": record.advisory_id,
        "status": record.status.value,
        "composite_score": record.composite_score,
        "source_name": record.source_name,
        "title": record.title,
        "article_url": record.article_url,
        "evidence_quote": record.evidence_quote,
        "created_at": record.created_at.isoformat(),
        "decided_at": record.decided_at.isoformat() if record.decided_at else None,
        "decided_by": record.decided_by,
        "decision_note": record.decision_note,
        "last_match_count": record.last_match_count,
    }


@triage_app.command("list")
def triage_list(
    triage_db: Annotated[
        Path,
        typer.Option("--triage-db", help="Path to SQLite triage queue database."),
    ] = Path(".zerobom-triage.sqlite"),
    status: Annotated[
        TriageStatus | None,
        typer.Option("--status", help="Filter by status: pending, approved, or rejected."),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", help="Maximum records to display."),
    ] = 100,
    format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Output format: terminal or json."),
    ] = OutputFormat.TERMINAL,
) -> None:
    """List persisted TRIAGE advisories and their review status."""
    try:
        if format == OutputFormat.SARIF:
            raise ValueError(
                "SARIF format is not supported for 'triage list'; use terminal or json."
            )
        store = TriageQueueStore(triage_db)
        items = store.list_items(status=status, limit=limit)
    except (TriageError, ValueError) as exc:
        typer.echo(f"Triage error: {exc}", err=True)
        raise typer.Exit(code=EXIT_ERROR) from exc

    if format == OutputFormat.JSON:
        typer.echo(json.dumps([_format_triage_record(r) for r in items], indent=2))
        raise typer.Exit(code=EXIT_OK)

    if not items:
        typer.echo("No triage items found.")
        raise typer.Exit(code=EXIT_OK)

    console = Console()
    table = Table(title="zerobom Triage Queue")
    table.add_column("ID", style="bold")
    table.add_column("Status")
    table.add_column("Score", justify="right")
    table.add_column("Source")
    table.add_column("Title")
    table.add_column("Hits", justify="right")
    for item in items:
        hits_str = str(item.last_match_count) if item.last_match_count is not None else "-"
        table.add_row(
            Text(item.triage_id),
            Text(item.status.value.upper()),
            Text(f"{item.composite_score:.2f}"),
            Text(item.source_name),
            Text(item.title[:60]),
            Text(hits_str),
        )
    console.print(table)
    raise typer.Exit(code=EXIT_OK)


@triage_app.command("show")
def triage_show(
    triage_id: Annotated[str, typer.Argument(help="Queued triage item ID (e.g., PRECVE-...).")],
    triage_db: Annotated[
        Path,
        typer.Option("--triage-db", help="Path to SQLite triage queue database."),
    ] = Path(".zerobom-triage.sqlite"),
    format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Output format: terminal or json."),
    ] = OutputFormat.TERMINAL,
) -> None:
    """Display full details and compiled OSV metadata for one queued triage item."""
    try:
        if format == OutputFormat.SARIF:
            raise ValueError(
                "SARIF format is not supported for 'triage show'; use terminal or json."
            )
        store = TriageQueueStore(triage_db)
        record = store.get(triage_id)
        if record is None:
            raise TriageError(f"Triage item {triage_id!r} was not found.")
    except (TriageError, ValueError) as exc:
        typer.echo(f"Triage error: {exc}", err=True)
        raise typer.Exit(code=EXIT_ERROR) from exc

    if format == OutputFormat.JSON:
        detail = _format_triage_record(record)
        detail["osv"] = json.loads(record.osv_json)
        typer.echo(json.dumps(detail, indent=2))
        raise typer.Exit(code=EXIT_OK)

    typer.echo(f"ID: {record.triage_id} [{record.status.value.upper()}]")
    typer.echo(f"Score: {record.composite_score:.4f} | Source: {record.source_name}")
    typer.echo(f"URL: {record.article_url}")
    if record.evidence_quote:
        typer.echo(f"Evidence Quote: {record.evidence_quote}")
    if record.decided_by:
        typer.echo(f"Decision: {record.status.value} by {record.decided_by}")
    raise typer.Exit(code=EXIT_OK)


@triage_app.command("approve")
def triage_approve(
    triage_id: Annotated[str, typer.Argument(help="Queued triage item ID to approve and scan.")],
    triage_db: Annotated[
        Path,
        typer.Option("--triage-db", help="Path to SQLite triage queue database."),
    ] = Path(".zerobom-triage.sqlite"),
    sbom: Annotated[
        Path | None,
        typer.Option("--sbom", help="Path to CycloneDX/SPDX JSON file or directory."),
    ] = None,
    backend: Annotated[
        str,
        typer.Option("--backend", help="Registered inventory backend plugin name."),
    ] = "local_sbom",
    backend_opt: Annotated[
        list[str] | None,
        typer.Option("--backend-opt", help="Repeatable KEY=VALUE configuration option."),
    ] = None,
    backend_config: Annotated[
        Path | None,
        typer.Option("--backend-config", help="Optional YAML/JSON backend config file."),
    ] = None,
    actor: Annotated[
        str,
        typer.Option("--actor", help="Human reviewer identifier recorded in audit history."),
    ] = "cli-operator",
    note: Annotated[
        str | None,
        typer.Option("--note", help="Optional decision note stored in triage history."),
    ] = None,
    webhook_url: Annotated[
        str | None,
        typer.Option("--webhook-url", help="Optional generic HTTPS webhook alert URL."),
    ] = None,
    webhook_secret: Annotated[
        str | None,
        typer.Option("--webhook-secret", help="Optional HMAC-SHA256 webhook signing secret."),
    ] = None,
    slack_webhook_url: Annotated[
        str | None,
        typer.Option("--slack-webhook-url", help="Optional Slack Incoming Webhook URL."),
    ] = None,
    allow_private_webhook: Annotated[
        bool,
        typer.Option("--allow-private-webhook", help="Permit private/loopback webhook targets."),
    ] = False,
    format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Output format: terminal, json, or sarif."),
    ] = OutputFormat.TERMINAL,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Optional path to write rendered scan output."),
    ] = None,
    json_out: Annotated[
        Path | None,
        typer.Option("--json-out", help="Optional path to write JSON output alongside --format."),
    ] = None,
    sarif_out: Annotated[
        Path | None,
        typer.Option("--sarif-out", help="Optional path to write SARIF output alongside --format."),
    ] = None,
    fail_on_hits: Annotated[
        bool,
        typer.Option("--fail-on-hits/--no-fail-on-hits", help="Exit 1 when matches are found."),
    ] = True,
) -> None:
    """Approve a TRIAGE advisory, run deterministic inventory matching, and alert on hits."""
    try:
        _require_configured_backend(
            backend,
            sbom,
            backend_opts=backend_opt or (),
            backend_config=backend_config,
        )
        store = TriageQueueStore(triage_db)
        with ExitStack() as stack:
            notifiers = _build_alert_notifiers(
                stack,
                webhook_url=webhook_url,
                webhook_secret=webhook_secret,
                slack_webhook_url=slack_webhook_url,
                allow_private_webhook=allow_private_webhook,
            )
            handler = TriageActionHandler(
                store,
                backend_factory=lambda: _create_backend(
                    backend,
                    sbom,
                    backend_opts=backend_opt or (),
                    backend_config=backend_config,
                ),
                alert_notifiers=notifiers,
            )
            result = handler.approve(triage_id, actor=actor, note=note)

        outcome = PipelineOutcome(
            credibility=CredibilityReport.model_validate_json(result.record.credibility_json),
            osv=OsvAdvisory.model_validate_json(result.record.osv_json),
            matches=result.matches,
        )
        _emit_outcomes(
            (outcome,),
            output_format=format,
            output_path=output,
            json_out=json_out,
            sarif_out=sarif_out,
        )
    except (
        TriageError,
        BackendError,
        SbomParseError,
        AlertDeliveryError,
        ValueError,
    ) as exc:
        typer.echo(f"Triage approve error: {exc}", err=True)
        raise typer.Exit(code=EXIT_ERROR) from exc

    raise typer.Exit(code=_exit_code_for_outcomes((outcome,), fail_on_hits=fail_on_hits))


@triage_app.command("reject")
def triage_reject(
    triage_id: Annotated[str, typer.Argument(help="Queued triage item ID to reject.")],
    triage_db: Annotated[
        Path,
        typer.Option("--triage-db", help="Path to SQLite triage queue database."),
    ] = Path(".zerobom-triage.sqlite"),
    actor: Annotated[
        str,
        typer.Option("--actor", help="Human reviewer identifier recorded in audit history."),
    ] = "cli-operator",
    note: Annotated[
        str | None,
        typer.Option("--note", help="Optional rejection rationale stored in triage history."),
    ] = None,
) -> None:
    """Reject a queued TRIAGE advisory without scanning or alerting."""
    try:
        store = TriageQueueStore(triage_db)
        handler = TriageActionHandler(store)
        result = handler.reject(triage_id, actor=actor, note=note)
    except TriageError as exc:
        typer.echo(f"Triage reject error: {exc}", err=True)
        raise typer.Exit(code=EXIT_ERROR) from exc

    state_label = "already decided" if result.already_decided else "rejected"
    typer.echo(
        f"Triage item {result.record.triage_id}: {state_label} ({result.record.status.value})."
    )
    raise typer.Exit(code=EXIT_OK)


@app.command("triage-worker")
def triage_worker(
    triage_db: Annotated[
        Path,
        typer.Option("--triage-db", help="Path to SQLite triage queue database."),
    ] = Path(".zerobom-triage.sqlite"),
    transport: Annotated[
        WorkerTransport,
        typer.Option("--transport", help="Callback transport: http or socket-mode."),
    ] = WorkerTransport.HTTP,
    host: Annotated[
        str,
        typer.Option("--host", help="Bind interface for HTTP webhook callback server."),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option("--port", help="TCP port for HTTP webhook callback server."),
    ] = 8787,
    callback_path: Annotated[
        str,
        typer.Option("--callback-path", help="HTTP POST path for Slack callbacks."),
    ] = "/slack/actions",
    signing_secret: Annotated[
        str | None,
        typer.Option(
            "--signing-secret",
            help="Slack App Signing Secret (or ZEROBOM_SLACK_SIGNING_SECRET).",
        ),
    ] = None,
    app_token: Annotated[
        str | None,
        typer.Option("--app-token", help="Slack App-level token for Socket Mode."),
    ] = None,
    bot_token: Annotated[
        str | None,
        typer.Option("--bot-token", help="Slack Bot token for Socket Mode."),
    ] = None,
    sbom: Annotated[
        Path | None,
        typer.Option("--sbom", help="Path to CycloneDX/SPDX JSON file or directory."),
    ] = None,
    backend: Annotated[
        str,
        typer.Option("--backend", help="Registered inventory backend plugin name."),
    ] = "local_sbom",
    backend_opt: Annotated[
        list[str] | None,
        typer.Option("--backend-opt", help="Repeatable KEY=VALUE configuration option."),
    ] = None,
    backend_config: Annotated[
        Path | None,
        typer.Option("--backend-config", help="Optional YAML/JSON backend config file."),
    ] = None,
    webhook_url: Annotated[
        str | None,
        typer.Option("--webhook-url", help="Optional generic webhook for post-approval hits."),
    ] = None,
    webhook_secret: Annotated[
        str | None,
        typer.Option("--webhook-secret", help="Optional HMAC-SHA256 webhook signing secret."),
    ] = None,
    slack_webhook_url: Annotated[
        str | None,
        typer.Option("--slack-webhook-url", help="Optional Slack Incoming Webhook for hits."),
    ] = None,
    allow_private_webhook: Annotated[
        bool,
        typer.Option("--allow-private-webhook", help="Permit private/loopback webhook targets."),
    ] = False,
) -> None:
    """Run the signed HTTP callback or Socket Mode listener for interactive triage buttons."""
    try:
        # Fail fast on malformed or missing backend config before opening network sockets.
        _require_configured_backend(
            backend,
            sbom,
            backend_opts=backend_opt or (),
            backend_config=backend_config,
        )
        store = TriageQueueStore(triage_db)

        with ExitStack() as stack:
            notifiers = _build_alert_notifiers(
                stack,
                webhook_url=webhook_url,
                webhook_secret=webhook_secret,
                slack_webhook_url=slack_webhook_url,
                allow_private_webhook=allow_private_webhook,
            )
            handler = TriageActionHandler(
                store,
                backend_factory=lambda: _create_backend(
                    backend,
                    sbom,
                    backend_opts=backend_opt or (),
                    backend_config=backend_config,
                ),
                alert_notifiers=notifiers,
            )

            if transport == WorkerTransport.SOCKET_MODE:
                resolved_app = app_token or os.environ.get("ZEROBOM_SLACK_APP_TOKEN") or ""
                resolved_bot = bot_token or os.environ.get("ZEROBOM_SLACK_BOT_TOKEN") or ""
                stop_event = run_socket_mode_worker(
                    handler,
                    app_token=resolved_app,
                    bot_token=resolved_bot,
                )
                typer.echo("zerobom Socket Mode triage worker running. Press Ctrl+C to stop.")
                try:
                    while not stop_event.wait(timeout=0.5):
                        pass
                except KeyboardInterrupt:
                    pass
                finally:
                    close_fn = getattr(stop_event, "close", None)
                    if callable(close_fn):
                        close_fn()
                raise typer.Exit(code=EXIT_OK)

            resolved_secret = signing_secret or os.environ.get("ZEROBOM_SLACK_SIGNING_SECRET") or ""
            with TriageWebhookServer(
                handler,
                signing_secret=resolved_secret,
                host=host,
                port=port,
                callback_path=callback_path,
            ) as server:
                bound_host, bound_port = server.server_address
                typer.echo(
                    f"zerobom signed Slack triage worker listening on "
                    f"http://{bound_host}:{bound_port}{callback_path}"
                )
                with suppress(KeyboardInterrupt):
                    server.serve_forever()
    except (
        TriageError,
        BackendError,
        AlertDeliveryError,
        RuntimeError,
        ValueError,
    ) as exc:
        typer.echo(f"Triage worker error: {exc}", err=True)
        raise typer.Exit(code=EXIT_ERROR) from exc

    raise typer.Exit(code=EXIT_OK)
