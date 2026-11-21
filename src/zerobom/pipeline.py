"""Decoupled end-to-end orchestration pipeline shared by CLI, demos, and benchmarks."""

from __future__ import annotations

import importlib.resources
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError

from zerobom.backends.base import InventoryBackend, match_advisory_with_backend
from zerobom.backends.local_sbom import _is_path_within_root
from zerobom.backends.sbom_parser import InMemoryComponentIndex, parse_sbom_bytes
from zerobom.extract.base import Extractor
from zerobom.ingest.fetcher import SafeHttpFetcher, compute_content_sha256
from zerobom.ingest.prefilter import prefilter_article
from zerobom.ingest.rss import poll_feed_items
from zerobom.ingest.state import IngestStateStore
from zerobom.models import (
    ExtractedAdvisory,
    InventoryComponent,
    MatchResult,
    OsvAdvisory,
    PackageQuery,
    PipelineOutcome,
    RawArticle,
    RoutingDecision,
    SourceFeedConfig,
    SourceTier,
)
from zerobom.verify.osv_compiler import compile_osv_advisory
from zerobom.verify.purl import RegistryChecker
from zerobom.verify.scorer import verify_advisory

MAX_OSV_FILE_BYTES = 10 * 1024 * 1024
MAX_OSV_FILES = 500


class _StaticExtractor:
    """Offline demo extractor returning a bundled :class:`ExtractedAdvisory`."""

    def __init__(self, advisory: ExtractedAdvisory) -> None:
        self._advisory = advisory

    @property
    def model_name(self) -> str:
        return self._advisory.extractor_model or "offline-demo-fixture"

    @property
    def prompt_version(self) -> str:
        return self._advisory.prompt_version or "v1.0"

    def extract(
        self,
        article: RawArticle,
        *,
        known_aliases: Sequence[str] = (),
    ) -> ExtractedAdvisory:
        del article, known_aliases
        return self._advisory


def _load_single_osv_file(file_path: Path, *, max_file_bytes: int) -> OsvAdvisory:
    """Read, size-check, and strictly validate a single OSV JSON file."""
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        raise ValueError(f"Failed to stat OSV file {file_path}: {exc}") from exc

    if size > max_file_bytes:
        raise ValueError(
            f"OSV file {file_path} exceeds maximum allowed size of {max_file_bytes} bytes."
        )

    try:
        raw_json = file_path.read_text(encoding="utf-8")
        return OsvAdvisory.model_validate_json(raw_json)
    except (OSError, UnicodeDecodeError, ValidationError, ValueError, RecursionError) as exc:
        raise ValueError(f"Invalid OSV JSON in {file_path}: {exc}") from exc


def load_osv_advisories(
    path: Path | str,
    *,
    max_file_bytes: int = MAX_OSV_FILE_BYTES,
    max_files: int = MAX_OSV_FILES,
) -> tuple[OsvAdvisory, ...]:
    """Load and validate OSV v1.6 JSON advisories from a file or directory.

    Args:
        path: Path to a single OSV JSON file or a directory of ``*.json`` files.
        max_file_bytes: Maximum byte size permitted per OSV JSON file.
        max_files: Maximum number of JSON files permitted in a directory scan.

    Returns:
        Tuple of validated :class:`OsvAdvisory` objects.

    Raises:
        ValueError: If ``path`` is missing, exceeds limits, contains invalid OSV JSON, or
            yields zero advisories.
    """
    if max_file_bytes < 1 or max_files < 1:
        raise ValueError("max_file_bytes and max_files must be >= 1")

    target = Path(path)
    if not target.exists():
        raise ValueError(f"OSV path does not exist: {target}")

    if target.is_file():
        return (_load_single_osv_file(target, max_file_bytes=max_file_bytes),)

    if not target.is_dir():
        raise ValueError(f"Unsupported OSV path type: {target}")

    candidates = sorted(target.rglob("*.json"))
    if len(candidates) > max_files:
        raise ValueError(
            f"Directory {target} contains {len(candidates)} JSON files, "
            f"exceeding max_files={max_files}."
        )

    advisories: list[OsvAdvisory] = []
    for candidate in candidates:
        # Skip symlinks and resolved paths escaping the scan root.
        if candidate.is_symlink() or not _is_path_within_root(candidate, target):
            continue
        if not candidate.is_file():
            continue
        advisories.append(_load_single_osv_file(candidate, max_file_bytes=max_file_bytes))

    if not advisories:
        raise ValueError(f"No OSV JSON files found in directory: {target}")

    return tuple(advisories)


def process_article(
    article: RawArticle,
    *,
    extractor: Extractor,
    backend: InventoryBackend | None = None,
    registry_checker: RegistryChecker | None = None,
    state_store: IngestStateStore | None = None,
    etag: str | None = None,
    last_modified: str | None = None,
    run_prefilter: bool = True,
    query_on_triage: bool = False,
    only_vulnerable: bool = True,
) -> PipelineOutcome:
    """Run an ingested :class:`RawArticle` through pre-filter, extraction, verification, and match.

    Args:
        article: Normalized article text and metadata.
        extractor: Narrow LLM (or fixture) extractor implementing :class:`Extractor`.
        backend: Optional inventory backend queried when routing passes the credibility gate.
        registry_checker: Optional upstream package registry verifier.
        state_store: Optional SQLite store updated after processing finishes.
        etag: Optional HTTP ``ETag`` validator persisted when marking ``state_store`` seen.
        last_modified: Optional HTTP ``Last-Modified`` validator persisted in ``state_store``.
        run_prefilter: Whether to gate non-vulnerability noise prior to invoking ``extractor``.
        query_on_triage: Whether ``TRIAGE`` advisories (0.50-0.74) also query ``backend``.
        only_vulnerable: Whether returned matches exclude patched/non-vulnerable versions.

    Returns:
        A :class:`PipelineOutcome` capturing every intermediate stage and inventory hits.
    """
    prefilter_res = None
    known_aliases: tuple[str, ...] = ()

    if run_prefilter:
        prefilter_res = prefilter_article(article)
        known_aliases = prefilter_res.extracted_aliases
        if not prefilter_res.passed:
            if state_store is not None:
                state_store.mark_seen(
                    article.url,
                    compute_content_sha256(article.body),
                    etag=etag,
                    last_modified=last_modified,
                    routing=RoutingDecision.DROP,
                )
            return PipelineOutcome(
                article=article,
                prefilter=prefilter_res,
                skipped_reason="Prefilter dropped non-vulnerability or marketing article.",
            )

    advisory = extractor.extract(article, known_aliases=known_aliases)
    credibility = verify_advisory(article, advisory, registry_checker=registry_checker)
    osv = compile_osv_advisory(advisory, credibility, article=article)

    should_query = (
        backend is not None
        and osv is not None
        and (
            credibility.routing == RoutingDecision.AUTO
            or (query_on_triage and credibility.routing == RoutingDecision.TRIAGE)
        )
    )
    matches: tuple[MatchResult, ...] = ()
    if should_query and backend is not None and osv is not None:
        matches = match_advisory_with_backend(osv, backend, only_vulnerable=only_vulnerable)

    if state_store is not None:
        state_store.mark_seen(
            article.url,
            compute_content_sha256(article.body),
            etag=etag,
            last_modified=last_modified,
            advisory_id=osv.id if osv is not None else None,
            routing=credibility.routing,
        )

    return PipelineOutcome(
        article=article,
        prefilter=prefilter_res,
        advisory=advisory,
        credibility=credibility,
        osv=osv,
        matches=matches,
    )


def scan_osv_files(
    osv_path: Path | str,
    *,
    backend: InventoryBackend,
    only_vulnerable: bool = True,
) -> tuple[PipelineOutcome, ...]:
    """Deterministically evaluate OSV JSON advisories against an inventory backend (zero LLM).

    Args:
        osv_path: Path to an OSV JSON file or directory of OSV JSON files.
        backend: Configured :class:`InventoryBackend` to query.
        only_vulnerable: Whether to omit non-vulnerable versions from returned matches.

    Returns:
        Tuple of :class:`PipelineOutcome` entries, one per loaded OSV advisory.
    """
    advisories = load_osv_advisories(osv_path)
    return tuple(
        PipelineOutcome(
            osv=adv,
            matches=match_advisory_with_backend(adv, backend, only_vulnerable=only_vulnerable),
        )
        for adv in advisories
    )


def check_url(
    url: str,
    *,
    fetcher: SafeHttpFetcher,
    extractor: Extractor,
    backend: InventoryBackend | None = None,
    source_name: str = "Manual URL",
    source_tier: SourceTier = SourceTier.UNKNOWN,
    registry_checker: RegistryChecker | None = None,
    state_store: IngestStateStore | None = None,
    run_prefilter: bool = True,
    query_on_triage: bool = False,
    only_vulnerable: bool = True,
) -> PipelineOutcome:
    """Fetch a single advisory URL securely and run it through the full verification pipeline.

    Args:
        url: HTTP/HTTPS URL of the security blog post.
        fetcher: SSRF-hardened :class:`SafeHttpFetcher`.
        extractor: Narrow LLM extractor.
        backend: Optional inventory backend to check against verified advisories.
        source_name: Publisher name attached to the fetched article.
        source_tier: Credibility tier weight assigned to the source.
        registry_checker: Optional upstream registry existence checker.
        state_store: Optional ingestion state store.
        run_prefilter: Whether to apply the pre-LLM keyword/regex filter.
        query_on_triage: Whether ``TRIAGE`` advisories also query ``backend``.
        only_vulnerable: Whether to return only vulnerable inventory matches.

    Returns:
        A :class:`PipelineOutcome` describing ingestion, verification, and inventory matches.
    """
    article, resp = fetcher.fetch_article(
        url,
        source_name=source_name,
        source_tier=source_tier,
    )
    if article is None:
        return PipelineOutcome(skipped_reason="Article unchanged (304 Not Modified).")

    return process_article(
        article,
        extractor=extractor,
        backend=backend,
        registry_checker=registry_checker,
        state_store=state_store,
        etag=resp.etag,
        last_modified=resp.last_modified,
        run_prefilter=run_prefilter,
        query_on_triage=query_on_triage,
        only_vulnerable=only_vulnerable,
    )


def watch_feeds(
    feeds: Sequence[SourceFeedConfig],
    *,
    fetcher: SafeHttpFetcher,
    extractor: Extractor,
    backend: InventoryBackend | None = None,
    state_store: IngestStateStore | None = None,
    registry_checker: RegistryChecker | None = None,
    run_prefilter: bool = True,
    query_on_triage: bool = False,
    only_vulnerable: bool = True,
) -> tuple[PipelineOutcome, ...]:
    """Poll allowlisted feeds and process newly discovered or edited articles end-to-end.

    Args:
        feeds: Allowlisted :class:`SourceFeedConfig` definitions.
        fetcher: SSRF-hardened :class:`SafeHttpFetcher`.
        extractor: Narrow LLM extractor.
        backend: Optional inventory backend queried on verified advisories.
        state_store: Optional SQLite state store for conditional fetch & edit detection.
        registry_checker: Optional upstream registry existence verifier.
        run_prefilter: Whether to run pre-LLM keyword/regex filtering.
        query_on_triage: Whether ``TRIAGE`` advisories also query ``backend``.
        only_vulnerable: Whether to return only vulnerable matches.

    Returns:
        Tuple of :class:`PipelineOutcome` objects for newly fetched/edited articles.
    """
    polled_items = poll_feed_items(
        feeds,
        fetcher=fetcher,
        state_store=state_store,
        mark_seen=False,
    )
    return tuple(
        process_article(
            item.article,
            extractor=extractor,
            backend=backend,
            registry_checker=registry_checker,
            state_store=state_store,
            etag=item.etag,
            last_modified=item.last_modified,
            run_prefilter=run_prefilter,
            query_on_triage=query_on_triage,
            only_vulnerable=only_vulnerable,
        )
        for item in polled_items
    )


class _StaticDemoBackend:
    """Offline demo backend exposing bundled SBOM components without host filesystem path leaks."""

    name = "local_sbom"

    def __init__(self, index: InMemoryComponentIndex) -> None:
        self._index = index

    def find_components(self, queries: Sequence[PackageQuery]) -> tuple[InventoryComponent, ...]:
        """Query indexed bundled demo components cleanly."""
        return self._index.find_components(queries)


def run_offline_demo() -> PipelineOutcome:
    """Run the zero-config offline demo using wheel-bundled advisory and SBOM fixtures.

    Returns:
        A :class:`PipelineOutcome` demonstrating quote verification, generic-name blocking,
        OSV compilation, and CycloneDX upstream/PURL SBOM matching.
    """
    data_pkg = importlib.resources.files("zerobom.data")
    article_raw = data_pkg.joinpath("demo_article.json").read_text(encoding="utf-8")
    extracted_raw = data_pkg.joinpath("demo_extracted.json").read_text(encoding="utf-8")
    sbom_bytes = data_pkg.joinpath("demo_sbom.cdx.json").read_bytes()

    article = RawArticle.model_validate_json(article_raw)
    advisory = ExtractedAdvisory.model_validate_json(extracted_raw)
    extractor = _StaticExtractor(advisory)

    demo_components = parse_sbom_bytes(
        sbom_bytes,
        asset_id="demo_sbom.cdx.json",
        backend="local_sbom",
        location="demo_sbom.cdx.json",
    )
    backend = _StaticDemoBackend(InMemoryComponentIndex(demo_components))
    return process_article(
        article,
        extractor=extractor,
        backend=backend,
        run_prefilter=True,
    )
