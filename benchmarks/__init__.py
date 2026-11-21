"""Two-tier public evaluation benchmark package for zerobom.

This package contains:
- Strict Pydantic contracts for offline adversarial fixtures and live extraction cases.
- Curated fair-use pre-CVE historical excerpts and marketing false-positive traps.
- The reproducible benchmark runner (`benchmarks.run_evals`).
"""

from benchmarks.schema import (
    BenchmarkCase,
    CaseEvaluation,
    EvalSummary,
    OfflineAdversarialCase,
    VersionProbe,
)

__all__ = [
    "BenchmarkCase",
    "CaseEvaluation",
    "EvalSummary",
    "OfflineAdversarialCase",
    "VersionProbe",
]
