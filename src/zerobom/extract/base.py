"""Pluggable narrow LLM extractor protocol and error contract."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from zerobom.models import ExtractedAdvisory, RawArticle


class ExtractionError(RuntimeError):
    """Raised when an extractor fails to return a schema-valid advisory."""


@runtime_checkable
class Extractor(Protocol):
    """Narrow ~15% structured extraction boundary isolated from deterministic verification.

    Implementations convert untrusted :class:`RawArticle` prose into candidate
    :class:`ExtractedAdvisory` claims with raw version strings and verbatim quotes; all package
    resolution, quote verification, and version math occur downstream in :mod:`zerobom.verify`.
    """

    @property
    def model_name(self) -> str:
        """Identifier of the underlying LLM model used for provenance tracking."""

    @property
    def prompt_version(self) -> str:
        """Version tag of the extraction prompt template."""

    def extract(
        self,
        article: RawArticle,
        *,
        known_aliases: Sequence[str] = (),
    ) -> ExtractedAdvisory:
        """Extract a candidate :class:`ExtractedAdvisory` from an ingested article.

        Args:
            article: Normalized ingested article to analyze.
            known_aliases: Optional pre-extracted CVE/GHSA identifiers from deterministic stages.

        Returns:
            Candidate :class:`ExtractedAdvisory` (with ``claims=()`` for non-vuln posts).

        Raises:
            ExtractionError: If extraction or schema validation fails after retries.
        """
