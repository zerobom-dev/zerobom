"""Lean OpenAI-compatible HTTP LLM extractor supporting Ollama, OpenAI, OpenRouter, and vLLM."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Sequence
from typing import Any

import httpx
from pydantic import Field, ValidationError, field_validator

from zerobom._version import DEFAULT_USER_AGENT
from zerobom.backends._http import read_bounded_response, redact_url_for_error
from zerobom.backends.base import BackendError
from zerobom.extract.base import ExtractionError
from zerobom.extract.prompts import (
    MAX_ARTICLE_CHARS,
    PROMPT_VERSION,
    build_extraction_messages,
)
from zerobom.ingest.prefilter import is_valid_advisory_alias
from zerobom.models import (
    _DISTRO_RELEASE_RE,
    ALLOWED_HTTP_SCHEMES,
    MAX_SUPPORTING_QUOTES,
    ArticleType,
    ExtractedAdvisory,
    ExtractedPackageClaim,
    RawArticle,
    StrictModel,
    VersionConstraint,
    VulnerabilitySeverity,
    _require_safe_text,
    _require_uri,
)

DEFAULT_LLM_BASE_URL = "http://localhost:11434/v1"
DEFAULT_LLM_MODEL = "llama3.2"
MAX_LLM_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_RETRY_ASSISTANT_CHARS = 2048

_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*\n?(.*?)\n?```$", re.IGNORECASE | re.DOTALL)
_CWE_ID_RE = re.compile(r"^CWE-[1-9]\d{0,4}$")
_NULLISH_STRINGS: frozenset[str] = frozenset({"", "n/a", "na", "none", "null", "unknown"})


class OpenAICompatConfig(StrictModel):
    """Configuration for :class:`OpenAICompatExtractor`.

    Attributes:
        base_url: OpenAI-compatible API base URL (e.g., ``http://localhost:11434/v1``).
        model: Model identifier sent to ``/chat/completions``.
        api_key: Optional bearer token (redacted from ``repr``).
        temperature: Sampling temperature in ``[0.0, 1.0]`` (defaults to deterministic ``0.0``).
        timeout_seconds: HTTP request timeout in seconds.
        max_retries: Number of schema/JSON correction retries after the initial attempt.
        max_article_chars: Character ceiling passed to :func:`prepare_article_window`.
        max_tokens: Maximum output tokens requested from the completions endpoint.
        use_json_response_format: Whether to send ``response_format={"type": "json_object"}``.
    """

    base_url: str = DEFAULT_LLM_BASE_URL
    model: str = DEFAULT_LLM_MODEL
    api_key: str | None = Field(default=None, repr=False)
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)
    timeout_seconds: float = Field(default=60.0, gt=0.0)
    max_retries: int = Field(default=2, ge=0, le=5)
    max_article_chars: int = Field(default=MAX_ARTICLE_CHARS, ge=100)
    max_tokens: int = Field(default=4096, ge=64, le=32768)
    use_json_response_format: bool = True

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, value: str) -> str:
        return _require_uri(value, "base_url", allowed_schemes=ALLOWED_HTTP_SCHEMES)

    @field_validator("model")
    @classmethod
    def _validate_model(cls, value: str) -> str:
        return _require_safe_text(value, "model")

    @classmethod
    def from_env(cls) -> OpenAICompatConfig:
        """Construct configuration from ``ZEROBOM_LLM_*`` (and ``OPENAI_API_KEY``) env vars.

        Returns:
            Configured :class:`OpenAICompatConfig` defaulting to local Ollama.
        """
        base_url = os.getenv("ZEROBOM_LLM_BASE_URL") or DEFAULT_LLM_BASE_URL
        model = os.getenv("ZEROBOM_LLM_MODEL") or DEFAULT_LLM_MODEL
        api_key = os.getenv("ZEROBOM_LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or None
        return cls(base_url=base_url, model=model, api_key=api_key)


def _strip_code_fences(raw_content: str) -> str:
    """Strip surrounding Markdown code fences if the LLM wrapped its JSON reply."""
    trimmed = raw_content.strip()
    if match := _CODE_FENCE_RE.match(trimmed):
        return match.group(1).strip()
    return trimmed


def _clean_optional_text(value: Any) -> str | None:
    """Normalize blank or placeholder strings (``N/A``, ``null``) to ``None``."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if stripped.lower() in _NULLISH_STRINGS:
        return None
    return stripped


def _clean_optional_uri(value: Any) -> str | None:
    """Validate optional extracted URLs, dropping unsafe/placeholder links rather than failing."""
    cleaned = _clean_optional_text(value)
    if cleaned is None:
        return None
    try:
        return _require_uri(cleaned, "url")
    except ValueError:
        return None


def _parse_severity(raw: Any) -> VulnerabilitySeverity:
    """Map raw LLM severity strings safely to :class:`VulnerabilitySeverity`."""
    if not isinstance(raw, str):
        return VulnerabilitySeverity.UNKNOWN
    candidate = raw.strip().upper()
    try:
        return VulnerabilitySeverity(candidate)
    except ValueError:
        return VulnerabilitySeverity.UNKNOWN


def _parse_article_type(raw: Any) -> ArticleType | None:
    """Map raw LLM ``article_type`` strings safely to :class:`ArticleType` or ``None``."""
    cleaned = _clean_optional_text(raw)
    if cleaned is None:
        return None
    try:
        return ArticleType(cleaned.lower())
    except ValueError:
        return None


def _ground_aliases(raw_aliases: Any, *, grounding_corpus: str) -> tuple[str, ...]:
    """Validate and deduplicate advisory aliases verbatim against ``grounding_corpus``."""
    if not isinstance(raw_aliases, list):
        return ()
    grounded: list[str] = []
    for alias in raw_aliases:
        if not isinstance(alias, str):
            continue
        canonical_alias = is_valid_advisory_alias(alias)
        if canonical_alias is None:
            continue
        # Zero-trust alias grounding: keep only valid IDs actually present in the article.
        if canonical_alias.casefold() not in grounding_corpus:
            continue
        if canonical_alias not in grounded:
            grounded.append(canonical_alias)
    return tuple(grounded)


def _ground_cwe_ids(raw_cwes: Any, *, grounding_corpus: str) -> tuple[str, ...]:
    """Validate and ground ``CWE-*`` identifiers strictly against ``grounding_corpus``."""
    if not isinstance(raw_cwes, list):
        return ()
    cwes: list[str] = []
    for item in raw_cwes:
        if not isinstance(item, str):
            continue
        val = item.strip().upper()
        if not _CWE_ID_RE.match(val):
            continue
        # Require verbatim CWE presence with boundary guards to block schema copying.
        cwe_pat = rf"(?<![a-z0-9]){re.escape(val.casefold())}(?![0-9])"
        if re.search(cwe_pat, grounding_corpus) is None:
            continue
        if val not in cwes:
            cwes.append(val)
    return tuple(cwes)


def _parse_constraints(raw_constraints: Any) -> tuple[VersionConstraint, ...]:
    """Normalize raw LLM version constraint dictionaries into strict models."""
    if raw_constraints is None:
        return ()
    if not isinstance(raw_constraints, list):
        raise ValueError("'version_constraints' must be a JSON array.")

    constraints: list[VersionConstraint] = []
    for item in raw_constraints:
        if isinstance(item, str):
            spec = item.strip()
            if spec:
                constraints.append(VersionConstraint(raw_specifier=spec))
            continue
        if not isinstance(item, dict):
            raise ValueError("Each version constraint must be an object or specifier string.")

        introduced = _clean_optional_text(item.get("introduced"))
        fixed = _clean_optional_text(item.get("fixed"))
        last_affected = _clean_optional_text(item.get("last_affected"))
        exact = _clean_optional_text(item.get("exact"))
        raw_specifier = _clean_optional_text(item.get("raw_specifier"))
        is_unbounded = bool(item.get("is_unbounded", False))

        has_any = any(
            v is not None for v in (introduced, fixed, last_affected, exact, raw_specifier)
        )
        if not has_any and not is_unbounded:
            continue

        constraints.append(
            VersionConstraint(
                introduced=introduced,
                fixed=fixed,
                last_affected=last_affected,
                exact=exact,
                raw_specifier=raw_specifier,
                is_unbounded=is_unbounded,
            )
        )
    return tuple(constraints)


def _clean_optional_distro_release(raw: Any) -> str | None:
    """Normalize optional ``distro_release`` values, dropping malformed labels cleanly."""
    cleaned = _clean_optional_text(raw)
    if cleaned is None:
        return None
    if (
        any(ord(ch) < 32 or ord(ch) == 127 for ch in cleaned)
        or ".." in cleaned
        or not _DISTRO_RELEASE_RE.match(cleaned)
    ):
        return None
    return cleaned


def _parse_supporting_quotes(raw_quotes: Any) -> tuple[str, ...]:
    """Normalize optional ``supporting_quotes`` list into bounded safe verbatim strings."""
    if not isinstance(raw_quotes, list):
        return ()
    quotes: list[str] = []
    for item in raw_quotes:
        if not isinstance(item, str) or not item.strip():
            continue
        if any((ord(ch) < 32 and ch not in "\t\n\r") or ord(ch) == 127 for ch in item):
            continue
        if item not in quotes:
            quotes.append(item)
        if len(quotes) >= MAX_SUPPORTING_QUOTES:
            break
    return tuple(quotes)


def _normalize_advisory_payload(
    payload: Any,
    *,
    article: RawArticle,
    known_aliases: Sequence[str],
    model_name: str,
    prompt_version: str,
) -> ExtractedAdvisory:
    """Validate and normalize parsed LLM JSON into a strict :class:`ExtractedAdvisory`."""
    del known_aliases  # Pre-filter aliases are non-binding prompt hints; LLM output is grounded.
    if not isinstance(payload, dict):
        raise ValueError("LLM JSON root must be a JSON object.")

    raw_claims = payload.get("claims", [])
    if not isinstance(raw_claims, list):
        raise ValueError("'claims' must be a JSON array.")

    grounding_corpus = f"{article.title}\n{article.body}\n{article.url}".casefold()

    claims: list[ExtractedPackageClaim] = []
    for item in raw_claims:
        if not isinstance(item, dict):
            raise ValueError("Each item in 'claims' must be a JSON object.")

        raw_pkg = item.get("raw_package_name")
        if not isinstance(raw_pkg, str) or not raw_pkg.strip():
            raise ValueError("Claim missing non-empty 'raw_package_name'.")
        raw_quote = item.get("evidence_quote")
        if not isinstance(raw_quote, str):
            raise ValueError("Claim missing string 'evidence_quote'.")

        claims.append(
            ExtractedPackageClaim(
                raw_package_name=raw_pkg.strip(),
                ecosystem=_clean_optional_text(item.get("ecosystem")),
                namespace=_clean_optional_text(item.get("namespace")),
                distro_release=_clean_optional_distro_release(item.get("distro_release")),
                version_constraints=_parse_constraints(item.get("version_constraints")),
                evidence_quote=raw_quote,
                supporting_quotes=_parse_supporting_quotes(item.get("supporting_quotes")),
                claim_aliases=_ground_aliases(
                    item.get("claim_aliases", ()),
                    grounding_corpus=grounding_corpus,
                ),
                fix_commit_url=_clean_optional_uri(item.get("fix_commit_url")),
                poc_url=_clean_optional_uri(item.get("poc_url")),
            )
        )

    raw_refs = payload.get("references", [])
    refs: list[str] = []
    if isinstance(raw_refs, list):
        for r in raw_refs:
            cleaned_ref = _clean_optional_uri(r)
            if cleaned_ref is not None and cleaned_ref not in refs:
                refs.append(cleaned_ref)

    cwes = _ground_cwe_ids(payload.get("cwe_ids", []), grounding_corpus=grounding_corpus)
    merged_aliases = _ground_aliases(
        payload.get("known_aliases", []),
        grounding_corpus=grounding_corpus,
    )

    title = _clean_optional_text(payload.get("title")) or article.title
    summary = _clean_optional_text(payload.get("summary")) or title
    details = payload.get("details")
    details_str = details.strip() if isinstance(details, str) else ""

    return ExtractedAdvisory(
        article_url=article.url,
        title=title,
        summary=summary,
        details=details_str,
        article_type=_parse_article_type(payload.get("article_type")),
        claims=tuple(claims),
        severity=_parse_severity(payload.get("severity")),
        cwe_ids=cwes,
        references=tuple(refs),
        known_aliases=merged_aliases,
        published_at=article.published_at,
        prompt_version=prompt_version,
        extractor_model=model_name,
    )


class OpenAICompatExtractor:
    """Narrow structured advisory extractor using any OpenAI-compatible HTTP endpoint."""

    def __init__(
        self,
        config: OpenAICompatConfig,
        *,
        client: httpx.Client | None = None,
    ) -> None:
        """Initialize the OpenAI-compatible HTTP extractor.

        Args:
            config: Endpoint URL, model name, optional API key, and retry configuration.
            client: Optional pre-configured ``httpx.Client`` (e.g., ``MockTransport`` in tests).
        """
        self._config = config
        self._owns_client = client is None
        self._client = (
            client
            if client is not None
            else httpx.Client(
                timeout=config.timeout_seconds,
                follow_redirects=False,
                headers={"User-Agent": DEFAULT_USER_AGENT},
            )
        )

    @property
    def client(self) -> httpx.Client:
        """Return the underlying ``httpx.Client`` instance."""
        return self._client

    @property
    def model_name(self) -> str:
        """Configured LLM model identifier."""
        return self._config.model

    @property
    def prompt_version(self) -> str:
        """Version tag of the extraction prompt template."""
        return PROMPT_VERSION

    def close(self) -> None:
        """Close the internal HTTP client if owned by this instance."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> OpenAICompatExtractor:
        """Enter context manager scope."""
        return self

    def __exit__(self, *_: object) -> None:
        """Close owned HTTP client resources upon exit."""
        self.close()

    def _call_completions(self, messages: list[dict[str, str]]) -> str:
        """POST chat completion request and return bounded raw assistant content text."""
        endpoint = f"{self._config.base_url.rstrip('/')}/chat/completions"
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._config.api_key:
            headers["Authorization"] = f"Bearer {self._config.api_key}"

        body: dict[str, Any] = {
            "model": self._config.model,
            "temperature": self._config.temperature,
            "max_tokens": self._config.max_tokens,
            "messages": messages,
        }
        if self._config.use_json_response_format:
            body["response_format"] = {"type": "json_object"}

        safe_endpoint = redact_url_for_error(endpoint, redact_path=False)
        try:
            status_code, _resp_headers, raw_body = read_bounded_response(
                self._client,
                "POST",
                endpoint,
                max_bytes=MAX_LLM_RESPONSE_BYTES,
                headers=headers,
                json_body=body,
                backend_name="llm_extractor",
                redact_url_path=False,
            )
        except (BackendError, httpx.HTTPError) as exc:
            # Never echo raw exception text that could contain URL query secrets (?key=...).
            raise ExtractionError(
                f"HTTP transport error ({type(exc).__name__}) calling extractor model "
                f"'{self._config.model}' at {safe_endpoint}"
            ) from exc

        if status_code >= 400:
            raise ExtractionError(
                f"LLM endpoint returned HTTP {status_code} for model '{self._config.model}'."
            )

        try:
            data = json.loads(raw_body.decode("utf-8"))
            content = data["choices"][0]["message"]["content"]
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
            KeyError,
            IndexError,
            TypeError,
        ) as exc:
            raise ExtractionError(f"Malformed OpenAI-compatible response envelope: {exc}") from exc

        if not isinstance(content, str) or not content.strip():
            raise ExtractionError("LLM response returned empty message content.")
        return content

    def extract(
        self,
        article: RawArticle,
        *,
        known_aliases: Sequence[str] = (),
    ) -> ExtractedAdvisory:
        """Extract a candidate :class:`ExtractedAdvisory` with schema-validated retry.

        Args:
            article: Normalized ingested article to extract claims from.
            known_aliases: Optional pre-extracted CVE/GHSA identifiers from pre-filtering.

        Returns:
            Validated :class:`ExtractedAdvisory` tagged with ``prompt_version`` and
            ``extractor_model``.

        Raises:
            ExtractionError: On HTTP failure or when JSON/schema validation fails past retries.
        """
        messages = build_extraction_messages(
            article,
            max_chars=self._config.max_article_chars,
            candidate_aliases=known_aliases,
        )

        last_error = "unknown parse error"
        for attempt in range(self._config.max_retries + 1):
            raw_content = self._call_completions(messages)
            cleaned_json = _strip_code_fences(raw_content)

            try:
                parsed = json.loads(cleaned_json)
                return _normalize_advisory_payload(
                    parsed,
                    article=article,
                    known_aliases=known_aliases,
                    model_name=self.model_name,
                    prompt_version=self.prompt_version,
                )
            except (
                json.JSONDecodeError,
                RecursionError,
                ValidationError,
                ValueError,
                TypeError,
            ) as exc:
                last_error = str(exc)
                if attempt >= self._config.max_retries:
                    break
                bounded_reply = raw_content[:MAX_RETRY_ASSISTANT_CHARS]
                messages = [
                    *messages,
                    {"role": "assistant", "content": bounded_reply},
                    {
                        "role": "user",
                        "content": (
                            "Your previous output was invalid JSON or violated the required "
                            f"schema ({last_error}). Respond with ONLY a valid JSON object "
                            "matching the schema."
                        ),
                    },
                ]

        raise ExtractionError(
            f"Extraction failed after {self._config.max_retries + 1} attempts: {last_error}"
        )
