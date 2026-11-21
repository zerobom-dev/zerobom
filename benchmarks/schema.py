"""Strict Pydantic contracts for zerobom benchmark datasets and results."""

from typing import Literal

from pydantic import Field

from zerobom.models import (
    ExtractedAdvisory,
    RawArticle,
    RegistryStatus,
    RoutingDecision,
    StrictModel,
)


class VersionProbe(StrictModel):
    """Deterministic component-version check against an evaluated advisory.

    Attributes:
        component_purl: Base Package URL (without version qualifier) to evaluate.
        installed_version: Installed package version tested against OSV ranges.
        expected_vulnerable: Whether deterministic evaluation should flag the version.
        description: Optional human-readable explanation of why the probe applies.
    """

    component_purl: str = Field(min_length=5, max_length=256)
    installed_version: str = Field(min_length=1, max_length=128)
    expected_vulnerable: bool
    description: str = Field(default="", max_length=256)


class BenchmarkCase(StrictModel):
    """Single live-extraction or marketing-trap evaluation case.

    Attributes:
        case_id: Unique stable identifier for filtering and regression tracking.
        category: Whether the excerpt is a pre-CVE advisory or a marketing trap.
        ecosystem_group: Logical grouping (for example ``pypi``, ``npm``, or ``marketing``).
        article: Canonical raw article fixture fed into the pipeline.
        expected_prefilter_pass: Expected boolean outcome from ``prefilter_article``.
        expected_routing: Target two-axis routing bucket (``auto``, ``triage``, or ``drop``).
        expected_purls: Ground-truth canonical Package URLs expected in the compiled OSV output.
        version_probes: Deterministic component checks validating extracted version bounds.
        notes: Concise rationale or benchmark provenance notes.
    """

    case_id: str = Field(min_length=1, max_length=128)
    category: Literal["precve", "marketing_trap"]
    ecosystem_group: str = Field(min_length=1, max_length=64)
    article: RawArticle
    expected_prefilter_pass: bool
    expected_routing: RoutingDecision
    expected_purls: tuple[str, ...] = ()
    version_probes: tuple[VersionProbe, ...] = ()
    notes: str = Field(default="", max_length=512)


class OfflineAdversarialCase(StrictModel):
    """Deterministic offline verification fixture testing golden and adversarial LLM outputs.

    Attributes:
        case_id: Unique stable identifier for the offline test case.
        case_kind: ``golden`` for valid advisories or ``adversarial`` for trap inputs.
        attack_vector: Named failure mode or safety invariant exercised by this case.
        article: Raw article text against which quote grounding and tier weights are computed.
        advisory: Simulated structured extraction returned by an LLM (potentially hostile).
        mock_registry_status: Map from canonical PURL to simulated registry lookup outcome.
        expected_routing: Target deterministic routing decision after verification.
        expected_accepted_purls: Canonical PURLs expected to survive verification.
        expected_dropped_count: Number of simulated LLM claims expected to be dropped.
        expect_osv_compiled: Whether an OSV advisory should be compiled from accepted claims.
        version_probes: Deterministic version probes executed against the compiled OSV advisory.
        notes: Concise description of the invariant verified by this fixture.
    """

    case_id: str = Field(min_length=1, max_length=128)
    case_kind: Literal["golden", "adversarial"]
    attack_vector: str = Field(min_length=1, max_length=128)
    article: RawArticle
    advisory: ExtractedAdvisory
    mock_registry_status: dict[str, RegistryStatus] = Field(default_factory=dict)
    expected_routing: RoutingDecision
    expected_accepted_purls: tuple[str, ...] = ()
    expected_dropped_count: int = Field(default=0, ge=0)
    expect_osv_compiled: bool = True
    version_probes: tuple[VersionProbe, ...] = ()
    notes: str = Field(default="", max_length=512)


class CaseEvaluation(StrictModel):
    """Scored outcome for a single benchmark case run.

    Attributes:
        case_id: Identifier matching the source benchmark fixture.
        suite: Evaluation mode under which this result was produced.
        category: Case category or attack vector label.
        expected_routing: Expected two-axis routing decision.
        actual_routing: Actual routing decision produced by verification/pipeline.
        routing_match: True when ``actual_routing == expected_routing``.
        expected_purls: Ground-truth canonical PURLs.
        actual_purls: Accepted canonical PURLs emitted by verification/pipeline.
        true_positives: Count of expected PURLs found in ``actual_purls``.
        false_positives: Count of unexpected PURLs emitted in ``actual_purls``.
        false_negatives: Count of expected PURLs missing from ``actual_purls``.
        grounded_claims: Number of extracted claims whose quote passed substring grounding.
        total_claims: Total number of extracted claims evaluated.
        hallucination_escaped: True if an adversarial/marketing trap yielded ``auto`` or
            emitted any unexpected PURL in ``auto``/``triage`` (or compiled unexpected claims).
        probe_passed: Number of version probes whose output matched expectation.
        probe_total: Total number of version probes executed for the case.
        prefilter_expected: Expected prefilter outcome when applicable.
        prefilter_actual: Observed prefilter outcome when applicable.
        error: Captured extraction or runtime error string, if any.
        reasons: Concise failure or verification diagnostic reasons.
    """

    case_id: str = Field(min_length=1, max_length=128)
    suite: Literal["offline", "live"]
    category: str = Field(min_length=1, max_length=128)
    expected_routing: RoutingDecision
    actual_routing: RoutingDecision
    routing_match: bool
    expected_purls: tuple[str, ...] = ()
    actual_purls: tuple[str, ...] = ()
    true_positives: int = Field(default=0, ge=0)
    false_positives: int = Field(default=0, ge=0)
    false_negatives: int = Field(default=0, ge=0)
    grounded_claims: int = Field(default=0, ge=0)
    total_claims: int = Field(default=0, ge=0)
    hallucination_escaped: bool = False
    probe_passed: int = Field(default=0, ge=0)
    probe_total: int = Field(default=0, ge=0)
    prefilter_expected: bool | None = None
    prefilter_actual: bool | None = None
    error: str | None = None
    reasons: tuple[str, ...] = ()


class EvalSummary(StrictModel):
    """Aggregate benchmark report across an offline or live suite run.

    Attributes:
        suite: Evaluation mode (``offline`` or ``live``).
        model_name: Extractor model identifier used in live runs, if applicable.
        prompt_version: Extractor prompt version recorded during live runs.
        total_cases: Number of evaluated cases.
        routing_accuracy: Fraction of cases where ``actual_routing == expected_routing``.
        package_precision: Micro-averaged PURL precision ``TP / (TP + FP)``.
        package_recall: Micro-averaged PURL recall ``TP / (TP + FN)``.
        package_f1: Harmonic mean of package precision and recall.
        probe_accuracy: Fraction of deterministic version probes yielding the expected verdict.
        quote_grounding_rate: Fraction of extracted claims with verified substring grounding.
        hallucination_escape_rate: Fraction of cases exhibiting hallucination escape.
        false_positive_trap_rate: Fraction of marketing traps that leaked past ``drop``.
        confusion_matrix: Nested ``expected -> actual -> count`` routing matrix.
        case_results: Individual per-case evaluation breakdowns.
        executed_at: Optional RFC 3339 UTC timestamp recorded for live runs (``None`` for offline
            runs so CI reports stay byte-for-byte deterministic).
        dataset_sha256: Optional SHA-256 digest of the dataset file(s) evaluated.
    """

    suite: Literal["offline", "live"]
    model_name: str | None = None
    prompt_version: str | None = None
    total_cases: int = Field(ge=0)
    routing_accuracy: float = Field(ge=0.0, le=1.0)
    package_precision: float = Field(ge=0.0, le=1.0)
    package_recall: float = Field(ge=0.0, le=1.0)
    package_f1: float = Field(ge=0.0, le=1.0)
    probe_accuracy: float = Field(ge=0.0, le=1.0)
    quote_grounding_rate: float = Field(ge=0.0, le=1.0)
    hallucination_escape_rate: float = Field(ge=0.0, le=1.0)
    false_positive_trap_rate: float = Field(ge=0.0, le=1.0)
    confusion_matrix: dict[str, dict[str, int]]
    case_results: tuple[CaseEvaluation, ...] = ()
    executed_at: str | None = None
    dataset_sha256: str | None = None
