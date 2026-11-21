"""Hardened HTTP/RSS ingestion, SQLite state tracking, and pre-LLM filtering."""

from zerobom.ingest.fetcher import (
    ALLOWED_CONTENT_TYPES,
    ALLOWED_FETCH_SCHEMES,
    MAX_REDIRECTS,
    MAX_RESPONSE_BYTES,
    FetchError,
    FetchResponse,
    SafeHttpFetcher,
    SsrfBlockedError,
    compute_content_sha256,
    extract_article_text,
    is_public_ip,
    validate_fetch_url,
)
from zerobom.ingest.prefilter import (
    extract_known_aliases,
    is_valid_advisory_alias,
    prefilter_article,
)
from zerobom.ingest.rss import (
    PolledArticle,
    discover_feed_entries,
    load_sources_config,
    parse_feed_entries,
    parse_html_index_entries,
    parse_sitemap_entries,
    poll_feed_items,
    poll_feeds,
)
from zerobom.ingest.state import IngestStateStore

__all__ = [
    "ALLOWED_CONTENT_TYPES",
    "ALLOWED_FETCH_SCHEMES",
    "MAX_REDIRECTS",
    "MAX_RESPONSE_BYTES",
    "FetchError",
    "FetchResponse",
    "IngestStateStore",
    "PolledArticle",
    "SafeHttpFetcher",
    "SsrfBlockedError",
    "compute_content_sha256",
    "discover_feed_entries",
    "extract_article_text",
    "extract_known_aliases",
    "is_public_ip",
    "is_valid_advisory_alias",
    "load_sources_config",
    "parse_feed_entries",
    "parse_html_index_entries",
    "parse_sitemap_entries",
    "poll_feed_items",
    "poll_feeds",
    "prefilter_article",
    "validate_fetch_url",
]
