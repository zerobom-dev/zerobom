"""Reproducible two-tier public evaluation benchmark runner for zerobom.

Supports two execution modes:
- ``offline``: 100% deterministic verification suite requiring zero network or LLM API keys.
- ``live``: End-to-end pre-filter + LLM extraction + deterministic verification + OSV
  range probe suite executed against any OpenAI-compatible endpoint (Ollama, OpenAI,
  OpenRouter, Gemini compat, vLLM).
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, TypeVar

from pydantic import TypeAdapter, ValidationError
from rich.console import Console
from rich.table import Table

try:
    from benchmarks.schema import (
        BenchmarkCase,
        CaseEvaluation,
        EvalSummary,
        OfflineAdversarialCase,
        VersionProbe,
    )
except ModuleNotFoundError:  # pragma: no cover - direct `python benchmarks/run_evals.py` run
    _REPO_ROOT = str(Path(__file__).resolve().parent.parent)
    if _REPO_ROOT not in sys.path:
        sys.path.insert(0, _REPO_ROOT)
    from benchmarks.schema import (
        BenchmarkCase,
        CaseEvaluation,
        EvalSummary,
        OfflineAdversarialCase,
        VersionProbe,
    )

from zerobom.extract import ExtractionError, Extractor, OpenAICompatConfig, OpenAICompatExtractor
from zerobom.models import (
    CredibilityReport,
    GroundingStatus,
    OsvAdvisory,
    RegistryStatus,
    RoutingDecision,
)
from zerobom.pipeline import process_article
from zerobom.verify import (
    HttpRegistryChecker,
    RegistryChecker,
    SqliteRegistryCache,
    compile_osv_advisory,
    evaluate_component_against_advisory,
    verify_advisory,
)

DEFAULT_DATASET_DIR = Path(__file__).resolve().parent / "datasets"
ROUTING_LABELS: tuple[str, ...] = (
    RoutingDecision.AUTO.value,
    RoutingDecision.TRIAGE.value,
    RoutingDecision.DROP.value,
)

_BENCHMARK_ADAPTER = TypeAdapter(tuple[BenchmarkCase, ...])
_OFFLINE_ADAPTER = TypeAdapter(tuple[OfflineAdversarialCase, ...])
_CaseT = TypeVar("_CaseT", BenchmarkCase, OfflineAdversarialCase)


class _MockRegistryChecker:
    """In-memory deterministic registry checker driven by case fixture maps."""

    def __init__(self, statuses: dict[str, RegistryStatus]) -> None:
        self._statuses = statuses

    def check(self, purl: str) -> RegistryStatus:
        """Return fixture registry status or ``SKIPPED`` when unspecified."""
        return self._statuses.get(purl, RegistryStatus.SKIPPED)


def _ensure_safe_output_path(path: Path) -> Path:
    """Reject control characters or parent-traversal segments in output file paths."""
    raw = str(path)
    if any(ord(ch) < 32 for ch in raw):
        raise ValueError("Output path contains invalid ASCII control characters.")
    if ".." in path.parts:
        raise ValueError(f"Output path must not contain '..' traversal segments: {path}")
    return path


def _compute_dataset_sha256(paths: Sequence[Path]) -> str | None:
    """Compute a deterministic SHA-256 digest over existing dataset files."""
    existing = [p for p in paths if p.is_file()]
    if not existing:
        return None
    hasher = hashlib.sha256()
    for path in sorted(existing):
        hasher.update(path.name.encode("utf-8"))
        hasher.update(b"\x00")
        hasher.update(path.read_bytes())
        hasher.update(b"\x00")
    return hasher.hexdigest()


def load_offline_cases(dataset_dir: Path | None = None) -> tuple[OfflineAdversarialCase, ...]:
    """Load and strictly validate deterministic offline golden and adversarial cases.

    Args:
        dataset_dir: Optional directory containing ``offline_adversarial.json``.

    Returns:
        Validated tuple of :class:`OfflineAdversarialCase` fixtures.
    """
    base_dir = dataset_dir or DEFAULT_DATASET_DIR
    path = base_dir / "offline_adversarial.json"
    return _OFFLINE_ADAPTER.validate_json(path.read_text(encoding="utf-8"))


def load_live_cases(
    dataset_dir: Path | None = None,
    *,
    include_precve: bool = True,
    include_marketing: bool = True,
) -> tuple[BenchmarkCase, ...]:
    """Load and validate live historical pre-CVE excerpts and marketing trap cases.

    Args:
        dataset_dir: Optional directory containing benchmark JSON dataset files.
        include_precve: Whether to include ``precve_cases.json``.
        include_marketing: Whether to include ``marketing_traps.json``.

    Returns:
        Combined tuple of validated :class:`BenchmarkCase` fixtures.
    """
    base_dir = dataset_dir or DEFAULT_DATASET_DIR
    cases: list[BenchmarkCase] = []
    if include_precve:
        raw_precve = (base_dir / "precve_cases.json").read_text(encoding="utf-8")
        cases.extend(_BENCHMARK_ADAPTER.validate_json(raw_precve))
    if include_marketing:
        raw_mkt = (base_dir / "marketing_traps.json").read_text(encoding="utf-8")
        cases.extend(_BENCHMARK_ADAPTER.validate_json(raw_mkt))
    return tuple(cases)


def _filter_cases(
    cases: tuple[_CaseT, ...],
    *,
    case_ids: Sequence[str] | None = None,
    limit: int | None = None,
) -> tuple[_CaseT, ...]:
    """Filter loaded benchmark cases by explicit case IDs and/or count limit."""
    selected: tuple[_CaseT, ...] = cases
    if case_ids:
        wanted = set(case_ids)
        selected = tuple(case for case in selected if case.case_id in wanted)
    if limit is not None:
        if limit < 0:
            raise ValueError("limit must be non-negative.")
        selected = selected[:limit]
    return selected


def _count_grounding(credibility: CredibilityReport | None) -> tuple[int, int]:
    """Return ``(verified_claims, total_claims)`` for a verification report."""
    if credibility is None or not credibility.claim_results:
        return (0, 0)
    verified = sum(
        1 for res in credibility.claim_results if res.grounding.status == GroundingStatus.VERIFIED
    )
    return (verified, len(credibility.claim_results))


def _evaluate_probes(
    osv: OsvAdvisory | None,
    probes: tuple[VersionProbe, ...],
) -> tuple[int, int, tuple[str, ...]]:
    """Run deterministic OSV range checks against all configured version probes."""
    if not probes:
        return (0, 0, ())
    if osv is None:
        return (
            0,
            len(probes),
            (f"Missing compiled OSV advisory for {len(probes)} expected version probe(s).",),
        )

    passed = 0
    failures: list[str] = []
    for probe in probes:
        match = evaluate_component_against_advisory(
            osv,
            probe.component_purl,
            probe.installed_version,
        )
        actual_vulnerable = bool(match is not None and match.is_vulnerable)
        if actual_vulnerable == probe.expected_vulnerable:
            passed += 1
        else:
            failures.append(
                f"Probe mismatch for {probe.component_purl}@{probe.installed_version}: "
                f"expected vulnerable={probe.expected_vulnerable}, got {actual_vulnerable}."
            )
    return (passed, len(probes), tuple(failures))


def _is_hallucination_escaped(
    *,
    expected_routing: RoutingDecision,
    actual_routing: RoutingDecision,
    expected_purls: tuple[str, ...],
    actual_purls: tuple[str, ...],
    osv_compiled: bool,
    expect_osv_compiled: bool | None = None,
) -> bool:
    """Determine whether an unverified/adversarial artifact bypassed deterministic gates."""
    expected_set = set(expected_purls)
    actual_set = set(actual_purls)
    unexpected_purls = actual_set - expected_set

    if expected_routing == RoutingDecision.DROP and not expected_set:
        return (
            actual_routing != RoutingDecision.DROP
            or bool(actual_set)
            or (expect_osv_compiled is False and osv_compiled)
        )

    return bool(
        (unexpected_purls and actual_routing in (RoutingDecision.AUTO, RoutingDecision.TRIAGE))
        or (expected_routing != RoutingDecision.AUTO and actual_routing == RoutingDecision.AUTO)
        or (expect_osv_compiled is False and osv_compiled)
    )


def _build_case_evaluation(
    *,
    case_id: str,
    suite: Literal["offline", "live"],
    category: str,
    expected_routing: RoutingDecision,
    actual_routing: RoutingDecision,
    expected_purls: tuple[str, ...],
    credibility: CredibilityReport | None,
    osv: OsvAdvisory | None,
    probes: tuple[VersionProbe, ...],
    prefilter_expected: bool | None = None,
    prefilter_actual: bool | None = None,
    expect_osv_compiled: bool | None = None,
    error: str | None = None,
    extra_reasons: tuple[str, ...] = (),
) -> CaseEvaluation:
    """Compute canonical per-case evaluation metrics shared by offline and live suites."""
    actual_purls = (
        tuple(
            dict.fromkeys(
                claim.purl.canonical_purl
                for claim in credibility.accepted_claims
                if claim.purl.canonical_purl is not None
            )
        )
        if credibility is not None
        else ()
    )

    expected_set = set(expected_purls)
    actual_set = set(actual_purls)
    tp = len(expected_set & actual_set)
    fp = len(actual_set - expected_set)
    fn = len(expected_set - actual_set)

    grounded, total_claims = _count_grounding(credibility)
    probe_passed, probe_total, probe_failures = _evaluate_probes(osv, probes)

    escaped = _is_hallucination_escaped(
        expected_routing=expected_routing,
        actual_routing=actual_routing,
        expected_purls=expected_purls,
        actual_purls=actual_purls,
        osv_compiled=osv is not None,
        expect_osv_compiled=expect_osv_compiled,
    )

    reasons: list[str] = list(extra_reasons)
    reasons.extend(probe_failures)
    if expect_osv_compiled is not None and (osv is not None) != expect_osv_compiled:
        reasons.append(f"Expected OSV compiled={expect_osv_compiled}, observed {osv is not None}.")
    if credibility is not None and credibility.routing != expected_routing:
        reasons.extend(credibility.reasons)
    if (
        suite == "live"
        and credibility is not None
        and (
            credibility.routing != expected_routing
            or credibility.dropped_claims
            or grounded < total_claims
        )
    ):
        for cr in credibility.claim_results:
            for msg in cr.reasons:
                if msg not in reasons:
                    reasons.append(msg)

    return CaseEvaluation(
        case_id=case_id,
        suite=suite,
        category=category,
        expected_routing=expected_routing,
        actual_routing=actual_routing,
        routing_match=(actual_routing == expected_routing),
        expected_purls=expected_purls,
        actual_purls=actual_purls,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        grounded_claims=grounded,
        total_claims=total_claims,
        hallucination_escaped=escaped,
        probe_passed=probe_passed,
        probe_total=probe_total,
        prefilter_expected=prefilter_expected,
        prefilter_actual=prefilter_actual,
        error=error,
        reasons=tuple(reasons),
    )


def _summarize_results(
    *,
    suite: Literal["offline", "live"],
    results: tuple[CaseEvaluation, ...],
    model_name: str | None = None,
    prompt_version: str | None = None,
    executed_at: str | None = None,
    dataset_sha256: str | None = None,
) -> EvalSummary:
    """Aggregate case evaluations into confusion matrix, P/R/F1, and safety rates."""
    total = len(results)
    matrix: dict[str, dict[str, int]] = {
        expected: {actual: 0 for actual in ROUTING_LABELS} for expected in ROUTING_LABELS
    }
    for item in results:
        matrix[item.expected_routing.value][item.actual_routing.value] += 1

    routing_hits = sum(1 for item in results if item.routing_match)
    tp = sum(item.true_positives for item in results)
    fp = sum(item.false_positives for item in results)
    fn = sum(item.false_negatives for item in results)

    precision = (tp / (tp + fp)) if (tp + fp) > 0 else (1.0 if fn == 0 else 0.0)
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else (1.0 if fp == 0 else 0.0)
    f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) > 0.0 else 0.0

    probe_passed = sum(item.probe_passed for item in results)
    probe_total = sum(item.probe_total for item in results)
    probe_accuracy = (probe_passed / probe_total) if probe_total > 0 else 1.0

    grounded_total = sum(item.grounded_claims for item in results)
    claim_total = sum(item.total_claims for item in results)
    grounding_rate = (grounded_total / claim_total) if claim_total > 0 else 1.0

    escapes = sum(1 for item in results if item.hallucination_escaped)
    escape_rate = (escapes / total) if total > 0 else 0.0

    marketing_cases = [
        item
        for item in results
        if item.category == "marketing_trap" or "marketing" in item.category
    ]
    marketing_leaks = sum(
        1 for item in marketing_cases if item.actual_routing != RoutingDecision.DROP
    )
    trap_rate = (marketing_leaks / len(marketing_cases)) if marketing_cases else 0.0

    return EvalSummary(
        suite=suite,
        model_name=model_name,
        prompt_version=prompt_version,
        total_cases=total,
        routing_accuracy=round((routing_hits / total) if total > 0 else 1.0, 4),
        package_precision=round(precision, 4),
        package_recall=round(recall, 4),
        package_f1=round(f1, 4),
        probe_accuracy=round(probe_accuracy, 4),
        quote_grounding_rate=round(grounding_rate, 4),
        hallucination_escape_rate=round(escape_rate, 4),
        false_positive_trap_rate=round(trap_rate, 4),
        confusion_matrix=matrix,
        case_results=results,
        executed_at=executed_at,
        dataset_sha256=dataset_sha256,
    )


def evaluate_offline_suite(
    cases: Sequence[OfflineAdversarialCase] | None = None,
    *,
    dataset_dir: Path | None = None,
    case_ids: Sequence[str] | None = None,
    limit: int | None = None,
) -> EvalSummary:
    """Evaluate the deterministic offline verification & OSV benchmark suite.

    Args:
        cases: Optional pre-loaded offline fixtures; loads ``offline_adversarial.json`` when
            omitted.
        dataset_dir: Alternate directory containing ``offline_adversarial.json``.
        case_ids: Optional list of case IDs to run.
        limit: Optional maximum number of cases to evaluate.

    Returns:
        An :class:`EvalSummary` summarizing deterministic safety and verification metrics.
    """
    loaded = tuple(cases) if cases is not None else load_offline_cases(dataset_dir)
    selected = _filter_cases(loaded, case_ids=case_ids, limit=limit)

    evaluations: list[CaseEvaluation] = []
    for case in selected:
        registry = _MockRegistryChecker(case.mock_registry_status)
        credibility = verify_advisory(case.article, case.advisory, registry_checker=registry)
        osv = compile_osv_advisory(case.advisory, credibility, article=case.article)

        extra_reasons: list[str] = []
        if len(credibility.dropped_claims) != case.expected_dropped_count:
            extra_reasons.append(
                f"Expected dropped_claims={case.expected_dropped_count}, "
                f"got {len(credibility.dropped_claims)}."
            )

        evaluations.append(
            _build_case_evaluation(
                case_id=case.case_id,
                suite="offline",
                category=f"{case.case_kind}:{case.attack_vector}",
                expected_routing=case.expected_routing,
                actual_routing=credibility.routing,
                expected_purls=case.expected_accepted_purls,
                credibility=credibility,
                osv=osv,
                probes=case.version_probes,
                expect_osv_compiled=case.expect_osv_compiled,
                extra_reasons=tuple(extra_reasons),
            )
        )

    base_dir = dataset_dir or DEFAULT_DATASET_DIR
    dataset_sha256 = (
        _compute_dataset_sha256((base_dir / "offline_adversarial.json",)) if cases is None else None
    )
    return _summarize_results(
        suite="offline",
        results=tuple(evaluations),
        model_name="deterministic-offline-fixtures",
        prompt_version=None,
        executed_at=None,
        dataset_sha256=dataset_sha256,
    )


def evaluate_live_suite(
    extractor: Extractor,
    cases: Sequence[BenchmarkCase] | None = None,
    *,
    dataset_dir: Path | None = None,
    registry_checker: RegistryChecker | None = None,
    case_ids: Sequence[str] | None = None,
    limit: int | None = None,
) -> EvalSummary:
    """Evaluate an :class:`Extractor` end-to-end against pre-CVE and marketing trap cases.

    Args:
        extractor: Structured LLM (or mock) extractor implementing :class:`Extractor`.
        cases: Optional pre-loaded live cases; loads ``precve_cases.json`` and
            ``marketing_traps.json`` when omitted.
        dataset_dir: Alternate dataset directory path.
        registry_checker: Optional package registry verifier passed to ``process_article``.
        case_ids: Optional subset of case IDs to execute.
        limit: Optional maximum number of cases to execute.

    Returns:
        An :class:`EvalSummary` containing extraction P/R/F1, grounding, trap, and routing metrics.
    """
    loaded = tuple(cases) if cases is not None else load_live_cases(dataset_dir)
    selected = _filter_cases(loaded, case_ids=case_ids, limit=limit)

    evaluations: list[CaseEvaluation] = []
    for case in selected:
        try:
            outcome = process_article(
                case.article,
                extractor=extractor,
                registry_checker=registry_checker,
                run_prefilter=True,
            )
        except ExtractionError as exc:
            evaluations.append(
                _build_case_evaluation(
                    case_id=case.case_id,
                    suite="live",
                    category=case.category,
                    expected_routing=case.expected_routing,
                    actual_routing=RoutingDecision.DROP,
                    expected_purls=case.expected_purls,
                    credibility=None,
                    osv=None,
                    probes=case.version_probes,
                    prefilter_expected=case.expected_prefilter_pass,
                    prefilter_actual=True,
                    error=str(exc),
                    extra_reasons=(f"ExtractionError: {exc}",),
                )
            )
            continue

        actual_routing = (
            outcome.credibility.routing if outcome.credibility is not None else RoutingDecision.DROP
        )
        prefilter_actual = outcome.prefilter.passed if outcome.prefilter is not None else None
        extra_reasons = (outcome.skipped_reason,) if outcome.skipped_reason else ()

        evaluations.append(
            _build_case_evaluation(
                case_id=case.case_id,
                suite="live",
                category=case.category,
                expected_routing=case.expected_routing,
                actual_routing=actual_routing,
                expected_purls=case.expected_purls,
                credibility=outcome.credibility,
                osv=outcome.osv,
                probes=case.version_probes,
                prefilter_expected=case.expected_prefilter_pass,
                prefilter_actual=prefilter_actual,
                extra_reasons=extra_reasons,
            )
        )

    base_dir = dataset_dir or DEFAULT_DATASET_DIR
    dataset_sha256 = (
        _compute_dataset_sha256((base_dir / "precve_cases.json", base_dir / "marketing_traps.json"))
        if cases is None
        else None
    )
    return _summarize_results(
        suite="live",
        results=tuple(evaluations),
        model_name=extractor.model_name,
        prompt_version=extractor.prompt_version,
        executed_at=datetime.now(UTC).isoformat(),
        dataset_sha256=dataset_sha256,
    )


def render_markdown_report(summary: EvalSummary) -> str:
    """Format an :class:`EvalSummary` as a GitHub-flavored Markdown benchmark report.

    Args:
        summary: Aggregated evaluation summary from offline or live execution.

    Returns:
        Markdown document suitable for CI job summaries, PR comments, or benchmark docs.
    """
    lines: list[str] = [
        f"# zerobom Benchmark Report ({summary.suite.upper()})",
        "",
        f"- **Model:** `{summary.model_name or 'N/A'}`",
        f"- **Prompt Version:** `{summary.prompt_version or 'N/A'}`",
        f"- **Total Cases:** `{summary.total_cases}`",
        f"- **Dataset SHA-256:** `{summary.dataset_sha256 or 'in-memory'}`",
        *([f"- **Executed At (UTC):** `{summary.executed_at}`"] if summary.executed_at else []),
        "",
        "## Headline Metrics",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Routing Accuracy | {summary.routing_accuracy * 100:.2f}% |",
        f"| Package Precision | {summary.package_precision * 100:.2f}% |",
        f"| Package Recall | {summary.package_recall * 100:.2f}% |",
        f"| Package F1 | {summary.package_f1 * 100:.2f}% |",
        f"| Version Probe Accuracy | {summary.probe_accuracy * 100:.2f}% |",
        f"| Quote Grounding Rate | {summary.quote_grounding_rate * 100:.2f}% |",
        f"| Hallucination Escape Rate | {summary.hallucination_escape_rate * 100:.2f}% |",
        f"| Marketing Trap False-Positive Rate | {summary.false_positive_trap_rate * 100:.2f}% |",
        "",
        "## Routing Confusion Matrix",
        "",
        "| Expected \\ Actual | auto | triage | drop |",
        "| --- | ---: | ---: | ---: |",
    ]
    for expected in ROUTING_LABELS:
        row = summary.confusion_matrix.get(expected, {})
        lines.append(
            f"| `{expected}` | {row.get('auto', 0)} | "
            f"{row.get('triage', 0)} | {row.get('drop', 0)} |"
        )

    lines.extend(
        [
            "",
            "## Case Breakdown",
            "",
            "| Case ID | Expected -> Actual | PURLs (TP/FP/FN) | Probes | Escape | Notes |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in summary.case_results:
        status = "OK" if item.routing_match and not item.hallucination_escaped else "MISMATCH"
        note = item.error or ("; ".join(item.reasons[:2]) if item.reasons else status)
        note_clean = note.replace("|", "\\|").replace("\n", " ")[:140]
        lines.append(
            f"| `{item.case_id}` | `{item.expected_routing.value}` -> "
            f"`{item.actual_routing.value}` | {item.true_positives}/{item.false_positives}/"
            f"{item.false_negatives} | {item.probe_passed}/{item.probe_total} | "
            f"{'YES' if item.hallucination_escaped else 'no'} | {note_clean} |"
        )
    lines.append("")
    return "\n".join(lines)


def _render_console_summary(summary: EvalSummary, console: Console | None = None) -> None:
    """Print structured Rich summary tables for terminal execution."""
    out = console or Console()
    metrics = Table(title=f"zerobom {summary.suite.upper()} Benchmark Summary")
    metrics.add_column("Metric", style="bold cyan")
    metrics.add_column("Value", justify="right")

    metrics.add_row("Model", summary.model_name or "N/A")
    metrics.add_row("Cases Evaluated", str(summary.total_cases))
    metrics.add_row("Routing Accuracy", f"{summary.routing_accuracy * 100:.2f}%")
    metrics.add_row(
        "Package P / R / F1",
        f"{summary.package_precision * 100:.1f}% / "
        f"{summary.package_recall * 100:.1f}% / "
        f"{summary.package_f1 * 100:.1f}%",
    )
    metrics.add_row("Version Probe Accuracy", f"{summary.probe_accuracy * 100:.2f}%")
    metrics.add_row("Quote Grounding Rate", f"{summary.quote_grounding_rate * 100:.2f}%")
    metrics.add_row("Hallucination Escape Rate", f"{summary.hallucination_escape_rate * 100:.2f}%")
    metrics.add_row(
        "Marketing Trap FP Rate",
        f"{summary.false_positive_trap_rate * 100:.2f}%",
    )
    out.print(metrics)

    matrix = Table(title="Routing Confusion Matrix (Expected -> Actual)")
    matrix.add_column("Expected \\ Actual", style="bold")
    for col in ROUTING_LABELS:
        matrix.add_column(col, justify="right")
    for expected in ROUTING_LABELS:
        row = summary.confusion_matrix[expected]
        matrix.add_row(expected, str(row["auto"]), str(row["triage"]), str(row["drop"]))
    out.print(matrix)

    flagged = [
        item
        for item in summary.case_results
        if (not item.routing_match)
        or item.hallucination_escaped
        or item.probe_passed != item.probe_total
        or item.error is not None
    ]
    if flagged:
        issues = Table(title="Flagged Cases")
        issues.add_column("Case ID", style="yellow")
        issues.add_column("Route")
        issues.add_column("Probes")
        issues.add_column("Details")
        for item in flagged:
            detail = item.error or "; ".join(item.reasons[:2]) or "Routing mismatch"
            issues.add_row(
                item.case_id,
                f"{item.expected_routing.value} -> {item.actual_routing.value}",
                f"{item.probe_passed}/{item.probe_total}",
                detail[:120],
            )
        out.print(issues)


def _write_optional_outputs(
    summary: EvalSummary,
    *,
    output_json: Path | None,
    output_markdown: Path | None,
) -> None:
    """Persist optional JSON and Markdown benchmark reports safely."""
    if output_json is not None:
        safe_json = _ensure_safe_output_path(output_json)
        safe_json.parent.mkdir(parents=True, exist_ok=True)
        safe_json.write_text(summary.model_dump_json(indent=2), encoding="utf-8")
    if output_markdown is not None:
        safe_md = _ensure_safe_output_path(output_markdown)
        safe_md.parent.mkdir(parents=True, exist_ok=True)
        safe_md.write_text(render_markdown_report(summary), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser for ``benchmarks.run_evals``."""
    parser = argparse.ArgumentParser(
        description="Run zerobom offline deterministic verification or live LLM extraction evals.",
    )
    parser.add_argument(
        "--mode",
        choices=("offline", "live"),
        default="offline",
        help="Execution tier: deterministic 'offline' CI suite or 'live' LLM extraction suite.",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help="OpenAI-compatible base URL (defaults to ZEROBOM_LLM_BASE_URL or Ollama).",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model ID passed to /chat/completions (defaults to ZEROBOM_LLM_MODEL or llama3.2).",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="Optional bearer API key (prefer ZEROBOM_LLM_API_KEY env var to avoid shell logs).",
    )
    parser.add_argument(
        "--verify-registry",
        action="store_true",
        help="Enable live package registry HTTP existence lookups during --mode live runs.",
    )
    parser.add_argument(
        "--registry-cache-db",
        type=Path,
        default=None,
        help="Optional SQLite cache DB path used when --verify-registry is enabled.",
    )
    parser.add_argument(
        "--case",
        dest="case_ids",
        action="append",
        default=None,
        help="Filter to specific case_id (repeatable).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Run only the first N selected benchmark cases.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Write complete EvalSummary JSON artifact to the specified path.",
    )
    parser.add_argument(
        "--output-markdown",
        type=Path,
        default=None,
        help="Write a GitHub-flavored Markdown report to the specified path.",
    )
    return parser


def _build_live_config(args: argparse.Namespace) -> OpenAICompatConfig:
    """Resolve OpenAI-compatible extractor config from env vars and explicit CLI overrides."""
    env_cfg = OpenAICompatConfig.from_env()
    return OpenAICompatConfig(
        base_url=args.base_url or env_cfg.base_url,
        model=args.model or env_cfg.model,
        api_key=args.api_key if args.api_key is not None else env_cfg.api_key,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for executing zerobom benchmark evaluations.

    Args:
        argv: Optional sequence of CLI arguments (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code: ``0`` on clean completion, ``1`` on deterministic regression or
        runtime failure, ``2`` on invalid arguments or configuration.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console()

    if args.limit is not None and args.limit < 0:
        console.print("[red]Error: --limit must be non-negative.[/red]")
        return 2

    if args.mode == "offline":
        summary = evaluate_offline_suite(case_ids=args.case_ids, limit=args.limit)
        _render_console_summary(summary, console=console)
        try:
            _write_optional_outputs(
                summary,
                output_json=args.output_json,
                output_markdown=args.output_markdown,
            )
        except (OSError, ValueError) as exc:
            console.print(f"[red]Failed to write benchmark report: {exc}[/red]")
            return 2

        offline_ok = (
            summary.total_cases > 0
            and summary.hallucination_escape_rate == 0.0
            and summary.routing_accuracy == 1.0
            and summary.probe_accuracy == 1.0
            and all(item.error is None and not item.reasons for item in summary.case_results)
        )
        return 0 if offline_ok else 1

    try:
        config = _build_live_config(args)
    except ValidationError as exc:
        console.print(f"[red]Invalid LLM configuration: {exc}[/red]")
        return 2

    cache = (
        SqliteRegistryCache(args.registry_cache_db) if args.registry_cache_db is not None else None
    )
    extractor = OpenAICompatExtractor(config)
    registry_checker: HttpRegistryChecker | None = (
        HttpRegistryChecker(cache=cache) if args.verify_registry else None
    )
    try:
        summary = evaluate_live_suite(
            extractor,
            registry_checker=registry_checker,
            case_ids=args.case_ids,
            limit=args.limit,
        )
    finally:
        if registry_checker is not None:
            registry_checker.close()

    _render_console_summary(summary, console=console)
    try:
        _write_optional_outputs(
            summary,
            output_json=args.output_json,
            output_markdown=args.output_markdown,
        )
    except (OSError, ValueError) as exc:
        console.print(f"[red]Failed to write benchmark report: {exc}[/red]")
        return 2

    if summary.total_cases == 0:
        console.print("[yellow]No matching benchmark cases selected.[/yellow]")
        return 1
    if summary.hallucination_escape_rate > 0.0:
        console.print(
            "[yellow]Warning: non-zero hallucination escape rate observed in live run.[/yellow]"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
