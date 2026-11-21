"""Structured JSON serialization for ``zerobom`` pipeline outcomes."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from zerobom.models import PipelineOutcome, RoutingDecision


def build_json_report(outcomes: Sequence[PipelineOutcome]) -> dict[str, Any]:
    """Convert pipeline outcomes into a schema-stable JSON-serializable report dictionary.

    Args:
        outcomes: Sequence of evaluated :class:`PipelineOutcome` instances.

    Returns:
        Dictionary containing ``schema``, aggregate ``summary`` counts, and per-outcome
        ``results`` with embedded standard OSV v1.6.7 dictionaries.
    """
    auto_count = 0
    triage_count = 0
    drop_count = 0
    vulnerable_hits = 0
    results: list[dict[str, Any]] = []

    for outcome in outcomes:
        if outcome.credibility is not None:
            if outcome.credibility.routing == RoutingDecision.AUTO:
                auto_count += 1
            elif outcome.credibility.routing == RoutingDecision.TRIAGE:
                triage_count += 1
            else:
                drop_count += 1
        elif outcome.skipped_reason is not None:
            drop_count += 1

        vulnerable_hits += len(outcome.vulnerable_matches)

        results.append(
            {
                "article_url": outcome.article.url if outcome.article is not None else None,
                "skipped_reason": outcome.skipped_reason,
                "prefilter": (
                    outcome.prefilter.model_dump(mode="json")
                    if outcome.prefilter is not None
                    else None
                ),
                "credibility": (
                    outcome.credibility.model_dump(mode="json")
                    if outcome.credibility is not None
                    else None
                ),
                "osv": outcome.osv.to_osv_dict() if outcome.osv is not None else None,
                "matches": [match.model_dump(mode="json") for match in outcome.matches],
            }
        )

    return {
        "schema": "zerobom.report/v1",
        "summary": {
            "total_analyzed": len(outcomes),
            "auto_count": auto_count,
            "triage_count": triage_count,
            "drop_count": drop_count,
            "vulnerable_hits": vulnerable_hits,
        },
        "results": results,
    }


def render_json_outcomes(outcomes: Sequence[PipelineOutcome], *, indent: int = 2) -> str:
    """Render pipeline outcomes as formatted JSON text.

    Args:
        outcomes: Sequence of evaluated :class:`PipelineOutcome` instances.
        indent: JSON indentation spaces.

    Returns:
        Formatted UTF-8 JSON report string.
    """
    return json.dumps(build_json_report(outcomes), indent=indent)
