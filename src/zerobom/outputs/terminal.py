"""Rich terminal rendering for ``zerobom`` outcomes with strict markup-injection safety."""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from zerobom.models import PipelineOutcome, RoutingDecision
from zerobom.verify.osv_compiler import _format_affected_ranges

# Strip ANSI/OSC-8 terminal escape sequences and C0/C1 controls from untrusted strings.
_ANSI_ESCAPE_RE = re.compile(r"\x1b(?:\][^\x07\x1b]*(?:\x07|\x1b\\)|\[[0-?]*[ -/]*[@-~]|[@-Z\\-_])")
_CTRL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]+")


def _safe_terminal_text(value: str) -> str:
    """Neutralize terminal ANSI/OSC-8 escape sequences and control characters."""
    without_ansi = _ANSI_ESCAPE_RE.sub("", value)
    return _CTRL_CHAR_RE.sub(" ", without_ansi).strip()


def _routing_style(routing: RoutingDecision) -> str:
    """Return Rich style name for a credibility routing outcome."""
    if routing == RoutingDecision.AUTO:
        return "bold green"
    if routing == RoutingDecision.TRIAGE:
        return "bold yellow"
    return "bold red"


def _compact_asset_label(raw: str) -> str:
    """Shorten long local file paths to relative paths or basenames for readable terminal tables."""
    if "://" in raw or len(raw) <= 32:
        return raw
    path_obj = Path(raw)
    try:
        rel = path_obj.resolve().relative_to(Path.cwd().resolve())
        rel_posix = rel.as_posix()
        return rel_posix if len(rel_posix) <= 32 else path_obj.name
    except (OSError, ValueError):
        return path_obj.name or raw


def render_terminal_outcomes(
    outcomes: Sequence[PipelineOutcome],
    *,
    console: Console | None = None,
) -> None:
    """Render advisory verification, grounded quotes, and SBOM hits cleanly to the terminal.

    All untrusted strings (article titles, URLs, evidence quotes, PURLs, versions) are wrapped
    in ``rich.text.Text`` objects to prevent terminal markup-injection vulnerabilities.

    Args:
        outcomes: Sequence of evaluated :class:`PipelineOutcome` entries.
        console: Optional ``rich.console.Console`` target (defaults to stdout console).
    """
    out = console if console is not None else Console()
    if not outcomes:
        out.print(Text("No articles or advisories processed.", style="dim"))
        return

    for outcome in outcomes:
        header_lines = Text()
        if outcome.article is not None:
            header_lines.append("Source: ", style="bold")
            safe_source = _safe_terminal_text(outcome.article.source_name)
            header_lines.append(f"{safe_source} ({outcome.article.source_tier.value})\n")
            header_lines.append("Title: ", style="bold")
            header_lines.append(f"{_safe_terminal_text(outcome.article.title)}\n")
            header_lines.append("URL: ", style="bold")
            header_lines.append(f"{_safe_terminal_text(outcome.article.url)}\n")

        if outcome.osv is not None:
            header_lines.append("OSV ID: ", style="bold")
            header_lines.append(f"{_safe_terminal_text(outcome.osv.id)}\n", style="cyan")
            if outcome.osv.aliases:
                header_lines.append("Aliases: ", style="bold")
                safe_aliases = ", ".join(_safe_terminal_text(a) for a in outcome.osv.aliases)
                header_lines.append(f"{safe_aliases}\n")
            for affected in outcome.osv.affected:
                header_lines.append("Affected: ", style="bold magenta")
                pkg_label = _safe_terminal_text(affected.package.purl or affected.package.name)
                if ":" in affected.package.ecosystem:
                    pkg_label = f"{pkg_label} [{_safe_terminal_text(affected.package.ecosystem)}]"
                range_summary = _format_affected_ranges(affected)
                if range_summary:
                    pkg_label = f"{pkg_label} ({_safe_terminal_text(range_summary)})"
                header_lines.append(f"{pkg_label}\n")

        if outcome.credibility is not None:
            cred = outcome.credibility
            header_lines.append("Credibility Score: ", style="bold")
            header_lines.append(f"{cred.composite_score:.4f} ")
            header_lines.append(
                f"[{cred.routing.value.upper()}]",
                style=_routing_style(cred.routing),
            )
            header_lines.append(
                f" (accepted={len(cred.accepted_claims)}, dropped={len(cred.dropped_claims)})\n"
            )
            seen_quotes: set[str] = set()
            for claim_res in cred.accepted_claims:
                for quote in (claim_res.claim.evidence_quote, *claim_res.claim.supporting_quotes):
                    safe_quote = _safe_terminal_text(quote)
                    if safe_quote in seen_quotes:
                        continue
                    seen_quotes.add(safe_quote)
                    header_lines.append("Verified Quote: ", style="bold green")
                    header_lines.append(f'"{safe_quote}"\n')
            for dropped_res in cred.dropped_claims:
                raw_reason = "; ".join(dropped_res.reasons) if dropped_res.reasons else "dropped"
                reason_text = _safe_terminal_text(raw_reason)
                raw_pkg = _safe_terminal_text(dropped_res.claim.raw_package_name)
                header_lines.append("Dropped Claim: ", style="bold red")
                header_lines.append(f"{raw_pkg} ({reason_text})\n")

        if outcome.skipped_reason is not None:
            header_lines.append("Status: ", style="bold yellow")
            header_lines.append(f"{_safe_terminal_text(outcome.skipped_reason)}\n")

        header_lines.rstrip()
        panel_title = (
            _safe_terminal_text(outcome.osv.id) if outcome.osv is not None else "zerobom Advisory"
        )
        out.print(Panel(header_lines, title=Text(panel_title, style="bold cyan"), expand=False))

        vulnerable = outcome.vulnerable_matches
        if vulnerable:
            table = Table(title="Matched Vulnerable Inventory Assets", show_lines=False)
            table.add_column("Matched PURL", style="magenta", no_wrap=True)
            table.add_column("Installed", style="red", overflow="fold")
            table.add_column("Fixed In", style="green", overflow="fold")
            table.add_column("Via", style="dim", no_wrap=True)
            table.add_column("Asset / SBOM", overflow="fold")

            for match in vulnerable:
                fixed = (
                    ", ".join(_safe_terminal_text(v) for v in match.fixed_versions)
                    if match.fixed_versions
                    else "-"
                )
                asset_loc = match.sbom_source or (
                    match.asset.asset_id if match.asset is not None else "-"
                )
                table.add_row(
                    Text(_safe_terminal_text(match.matched_purl)),
                    Text(_safe_terminal_text(match.installed_version)),
                    Text(fixed),
                    Text(_safe_terminal_text(match.matched_via)),
                    Text(_safe_terminal_text(_compact_asset_label(asset_loc))),
                )
            out.print(table)
        else:
            out.print(Text("No vulnerable inventory matches found.", style="green"))
