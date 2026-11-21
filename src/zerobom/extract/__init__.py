"""Isolated narrow LLM structured advisory extraction layer."""

from zerobom.extract.base import ExtractionError, Extractor
from zerobom.extract.openai_compat import OpenAICompatConfig, OpenAICompatExtractor
from zerobom.extract.prompts import (
    MAX_ARTICLE_CHARS,
    PROMPT_VERSION,
    build_extraction_messages,
    prepare_article_window,
    sanitize_untrusted_delimiter,
)

__all__ = [
    "MAX_ARTICLE_CHARS",
    "PROMPT_VERSION",
    "ExtractionError",
    "Extractor",
    "OpenAICompatConfig",
    "OpenAICompatExtractor",
    "build_extraction_messages",
    "prepare_article_window",
    "sanitize_untrusted_delimiter",
]
