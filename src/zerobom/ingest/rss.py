"""Safe YAML feed config loading, RSS/sitemap/HTML discovery, and conditional polling."""

from __future__ import annotations

import re
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urldefrag, urljoin, urlparse
from xml.parsers import expat

import feedparser
import yaml
from pydantic import ValidationError

from zerobom.ingest.fetcher import FetchError, SafeHttpFetcher, compute_content_sha256
from zerobom.ingest.state import IngestStateStore
from zerobom.models import (
    FeedEntry,
    FeedKind,
    RawArticle,
    SourceFeedConfig,
    SourcesConfig,
    SourceTier,
    _url_origin,
)
from zerobom.verify.osv_compiler import canonicalize_url

MAX_FEED_ENTRIES = 100
MAX_SOURCES_YAML_BYTES = 1024 * 1024
MAX_SITEMAP_URLS = 5000
MAX_HTML_LINKS = 5000

_HTML_CONTENT_TYPES: frozenset[str] = frozenset({"text/html", "application/xhtml+xml"})
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]+")
_WHITESPACE_RE = re.compile(r"\s+")


class _XmlPolicyError(FetchError):
    """Internal sentinel error raised when XML contains disallowed DOCTYPE/ENTITY nodes."""


@dataclass(frozen=True)
class PolledArticle:
    """Fetched candidate article paired with HTTP cache validators and content digest.

    Used by :func:`poll_feed_items` and :func:`zerobom.pipeline.watch_feeds` so callers can
    persist :class:`IngestStateStore` markers only after downstream extraction succeeds.

    Attributes:
        article: Ingested and cleaned :class:`RawArticle`.
        content_sha256: Hexadecimal SHA-256 digest of ``article.body``.
        etag: Optional HTTP ``ETag`` header from the article response.
        last_modified: Optional HTTP ``Last-Modified`` header from the article response.
    """

    article: RawArticle
    content_sha256: str
    etag: str | None = None
    last_modified: str | None = None


def _is_same_origin(url_a: str, url_b: str) -> bool:
    """Return True if two HTTP/HTTPS URLs share scheme, normalized hostname, and port."""
    return _url_origin(url_a) == _url_origin(url_b)


def _matches_url_prefix(candidate_url: str, url_prefix: str) -> bool:
    """Return True if ``candidate_url`` matches origin and segment-safe path of ``url_prefix``."""
    if not _is_same_origin(candidate_url, url_prefix):
        return False

    cand_path = urlparse(candidate_url).path or "/"
    pref_path = urlparse(url_prefix).path or "/"
    if pref_path.endswith("/"):
        return cand_path.startswith(pref_path)
    return cand_path == pref_path or cand_path.startswith(f"{pref_path}/")


def _title_from_url_slug(url: str) -> str:
    """Derive a clean readable fallback title from a post URL path segment."""
    path = urlparse(url).path.rstrip("/")
    slug = path.rsplit("/", 1)[-1] if path else ""
    for ext in (".html", ".htm"):
        if slug.lower().endswith(ext):
            slug = slug[: -len(ext)]
            break
    cleaned = _CONTROL_CHAR_RE.sub(" ", slug.replace("-", " ").replace("_", " "))
    collapsed = _WHITESPACE_RE.sub(" ", cleaned).strip()
    if collapsed:
        return collapsed[:120]
    return "Untitled Advisory"


def _clean_anchor_title(raw_text: str, fallback_url: str) -> str:
    """Sanitize HTML anchor text or fall back to URL slug when blank or tiny."""
    stripped = _CONTROL_CHAR_RE.sub(" ", raw_text)
    collapsed = _WHITESPACE_RE.sub(" ", stripped).strip()
    if len(collapsed) >= 3:
        return collapsed[:200]
    return _title_from_url_slug(fallback_url)


def _parse_iso_datetime(raw: str | None) -> datetime | None:
    """Parse ``YYYY-MM-DD`` or ISO 8601 / RFC 3339 date string into a UTC-aware ``datetime``."""
    if not raw:
        return None
    cleaned = raw.strip()
    if not cleaned:
        return None
    normalized = f"{cleaned[:-1]}+00:00" if cleaned.endswith(("Z", "z")) else cleaned
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _decode_xml_for_policy_scan(xml_bytes: bytes) -> str:
    """Decode XML bytes using BOM or NUL-byte heuristic for fallback DTD/ENTITY scanning."""
    if xml_bytes.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return xml_bytes.decode("utf-32", errors="ignore")
    if xml_bytes.startswith((b"\xff\xfe", b"\xfe\xff")):
        return xml_bytes.decode("utf-16", errors="ignore")
    if b"\x00" in xml_bytes[:256]:
        # Detect BOM-less UTF-16 LE/BE payloads before falling back to UTF-8.
        even_nuls = sum(1 for b in xml_bytes[:256:2] if b == 0)
        odd_nuls = sum(1 for b in xml_bytes[1:256:2] if b == 0)
        if even_nuls > odd_nuls:
            return xml_bytes.decode("utf-16-be", errors="ignore")
        if odd_nuls > even_nuls:
            return xml_bytes.decode("utf-16-le", errors="ignore")
    return xml_bytes.decode("utf-8", errors="ignore")


def _reject_xml_xxe(xml_bytes: bytes, source_name: str) -> None:
    """Fail closed if XML input declares DOCTYPE or ENTITY directives in any encoding.

    Runs ``expat`` before fallback byte regex scanning so valid feeds containing literal
    ``<!DOCTYPE html>`` or ``<!ENTITY ...>`` examples inside ``<![CDATA[...]]>`` post bodies
    are accepted as character data, while real DTD/entity declarations and malformed XML with
    DOCTYPE/ENTITY declarations still fail closed.
    """

    def _on_disallowed(*_args: Any) -> None:
        raise _XmlPolicyError(
            f"Feed {source_name!r} rejected: XML contains disallowed DOCTYPE/ENTITY declaration."
        )

    def _on_disallowed_ext(*_args: Any) -> int:
        raise _XmlPolicyError(
            f"Feed {source_name!r} rejected: XML contains disallowed external entity reference."
        )

    parser = expat.ParserCreate(namespace_separator=" ")
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.StartDoctypeDeclHandler = _on_disallowed
    parser.EntityDeclHandler = _on_disallowed
    parser.UnparsedEntityDeclHandler = _on_disallowed
    parser.NotationDeclHandler = _on_disallowed
    parser.ExternalEntityRefHandler = _on_disallowed_ext

    try:
        parser.Parse(xml_bytes, True)
    except _XmlPolicyError:
        raise
    except expat.ExpatError:
        # Bozo/truncated feeds or non-UTF-8 encodings without BOM can fail expat mid-stream;
        # run a BOM/NUL-aware scan so encoded DOCTYPE/ENTITY declarations cannot slip past.
        decoded = _decode_xml_for_policy_scan(xml_bytes)
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", decoded, re.IGNORECASE):
            raise _XmlPolicyError(
                f"Feed {source_name!r} rejected: XML contains disallowed "
                "DOCTYPE/ENTITY declaration."
            ) from None


def load_sources_config(path: Path | str) -> SourcesConfig:
    """Load and strictly validate a ``sources.yaml`` feed allowlist using ``yaml.safe_load``.

    Args:
        path: Path to the YAML sources configuration file.

    Returns:
        Validated :class:`SourcesConfig` object.

    Raises:
        ValueError: If the file is missing, exceeds ``MAX_SOURCES_YAML_BYTES``, contains invalid
            YAML, or fails strict Pydantic schema validation.
    """
    yaml_path = Path(path)
    if not yaml_path.is_file():
        raise ValueError(f"Sources configuration file does not exist: {yaml_path}")

    size = yaml_path.stat().st_size
    if size > MAX_SOURCES_YAML_BYTES:
        raise ValueError(
            f"Sources file {yaml_path} exceeds max size of {MAX_SOURCES_YAML_BYTES} bytes."
        )

    try:
        raw_text = yaml_path.read_text(encoding="utf-8")
        loaded = yaml.safe_load(raw_text)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Failed to parse YAML in {yaml_path}: {exc}") from exc

    if not isinstance(loaded, dict):
        raise ValueError(f"Root of {yaml_path} must be a YAML mapping.")

    raw_feeds = loaded.get("feeds", [])
    if not isinstance(raw_feeds, list):
        raise ValueError("'feeds' must be a list in sources.yaml.")

    parsed_feeds: list[SourceFeedConfig] = []
    for item in raw_feeds:
        if not isinstance(item, dict):
            raise ValueError("Each entry in 'feeds' must be a YAML mapping.")

        raw_tier = item.get("tier", SourceTier.TIER_2.value)
        try:
            tier = raw_tier if isinstance(raw_tier, SourceTier) else SourceTier(str(raw_tier))
        except ValueError as exc:
            raise ValueError(f"Invalid source tier {raw_tier!r} in {yaml_path}.") from exc

        raw_kind = item.get("kind", FeedKind.RSS.value)
        try:
            kind = (
                raw_kind
                if isinstance(raw_kind, FeedKind)
                else FeedKind(str(raw_kind).strip().lower())
            )
        except ValueError as exc:
            raise ValueError(f"Invalid source feed kind {raw_kind!r} in {yaml_path}.") from exc

        raw_prefix = item.get("url_prefix")
        if raw_prefix is not None and not isinstance(raw_prefix, str):
            raise ValueError(f"'url_prefix' must be a string in {yaml_path}.")

        raw_tags = item.get("tags", [])
        if not isinstance(raw_tags, list) or not all(isinstance(t, str) for t in raw_tags):
            raise ValueError("'tags' in sources.yaml feed entry must be a list of strings.")

        feed_kwargs: dict[str, Any] = {
            "name": item.get("name"),
            "url": item.get("url"),
            "tier": tier,
            "kind": kind,
            "url_prefix": raw_prefix,
            "enabled": item.get("enabled", True),
            "tags": tuple(raw_tags),
        }
        try:
            parsed_feeds.append(SourceFeedConfig(**feed_kwargs))
        except ValidationError as exc:
            raise ValueError(f"Invalid feed configuration in {yaml_path}: {exc}") from exc

    version = loaded.get("version", 1)
    return SourcesConfig(version=version, feeds=tuple(parsed_feeds))


def _parse_struct_time(raw_struct: Any) -> datetime:
    """Convert feedparser's 9-tuple ``struct_time`` safely to a UTC ``datetime``."""
    if isinstance(raw_struct, time.struct_time):
        try:
            return datetime(*raw_struct[:6], tzinfo=UTC)
        except ValueError:
            pass
    return datetime.now(UTC)


def parse_feed_entries(
    feed_bytes: bytes,
    feed: SourceFeedConfig,
    *,
    max_entries: int = MAX_FEED_ENTRIES,
) -> tuple[FeedEntry, ...]:
    """Parse RSS or Atom XML bytes into validated, deduplicated :class:`FeedEntry` records.

    Args:
        feed_bytes: Raw XML bytes fetched from an RSS/Atom endpoint.
        feed: Source feed configuration providing publisher name, tier, and optional prefix.
        max_entries: Maximum number of entries returned from a single feed.

    Returns:
        Deduplicated tuple of validated :class:`FeedEntry` items.

    Raises:
        FetchError: If XML contains ``<!DOCTYPE`` or ``<!ENTITY``, or ``max_entries < 1``.
    """
    if max_entries < 1:
        raise FetchError("max_entries must be >= 1")

    _reject_xml_xxe(feed_bytes, feed.name)

    parsed_feed = feedparser.parse(feed_bytes)
    entries = getattr(parsed_feed, "entries", []) or []

    results: list[FeedEntry] = []
    seen_urls: set[str] = set()

    for raw_entry in entries:
        if len(results) >= max_entries:
            break
        raw_link = raw_entry.get("link")
        raw_title = raw_entry.get("title") or "Untitled Advisory"
        raw_summary = raw_entry.get("summary") or raw_entry.get("description") or ""
        if not isinstance(raw_link, str):
            continue

        published_at = _parse_struct_time(
            raw_entry.get("published_parsed") or raw_entry.get("updated_parsed")
        )
        try:
            entry = FeedEntry(
                url=raw_link,
                title=str(raw_title),
                summary=str(raw_summary),
                published_at=published_at,
                source_name=feed.name,
                source_tier=feed.tier,
            )
        except ValidationError:
            # Skip individual entries with unsafe schemes (e.g., javascript:) or malformed titles.
            continue

        if feed.url_prefix is not None and not _matches_url_prefix(entry.url, feed.url_prefix):
            continue

        canonical = canonicalize_url(entry.url)
        if canonical in seen_urls:
            continue
        seen_urls.add(canonical)
        results.append(entry)

    return tuple(results)


def parse_sitemap_entries(
    xml_bytes: bytes,
    feed: SourceFeedConfig,
    *,
    max_entries: int = MAX_FEED_ENTRIES,
) -> tuple[FeedEntry, ...]:
    """Parse an XML sitemap (``<urlset>``) into validated, date-sorted :class:`FeedEntry` items.

    Rejects XML DOCTYPE/ENTITY directives, applies optional ``feed.url_prefix`` filtering,
    deduplicates canonical URLs, and sorts entries carrying ``<lastmod>`` newest-first prior
    to enforcing ``max_entries``.

    Args:
        xml_bytes: Raw XML sitemap payload bytes.
        feed: Source feed configuration providing name, tier, and optional ``url_prefix``.
        max_entries: Maximum number of entries returned.

    Returns:
        Deduplicated tuple of validated :class:`FeedEntry` items.

    Raises:
        FetchError: If XML contains DOCTYPE/ENTITY, is malformed, or ``max_entries < 1``.
    """
    if max_entries < 1:
        raise FetchError("max_entries must be >= 1")

    _reject_xml_xxe(xml_bytes, feed.name)

    raw_items: list[tuple[str, str | None]] = []
    in_url = False
    active_field: str | None = None
    loc_buf: list[str] = []
    lastmod_buf: list[str] = []

    def _local_name(tag_name: str) -> str:
        return tag_name.rsplit(" ", 1)[-1].lower()

    def _on_doctype(*_args: Any) -> None:
        raise _XmlPolicyError(
            f"Feed {feed.name!r} rejected: XML contains disallowed DOCTYPE declaration."
        )

    def _on_entity(*_args: Any) -> None:
        raise _XmlPolicyError(
            f"Feed {feed.name!r} rejected: XML contains disallowed ENTITY declaration."
        )

    def _on_start(name: str, _attrs: dict[str, str]) -> None:
        nonlocal in_url, active_field
        local = _local_name(name)
        if local == "url" and len(raw_items) < MAX_SITEMAP_URLS:
            in_url = True
            active_field = None
            loc_buf.clear()
            lastmod_buf.clear()
        elif in_url and local in {"loc", "lastmod"}:
            active_field = local

    def _on_char(data: str) -> None:
        if not in_url or active_field is None:
            return
        if active_field == "loc":
            loc_buf.append(data)
        elif active_field == "lastmod":
            lastmod_buf.append(data)

    def _on_end(name: str) -> None:
        nonlocal in_url, active_field
        local = _local_name(name)
        if in_url and local == active_field:
            active_field = None
        elif local == "url" and in_url:
            loc_val = "".join(loc_buf).strip()
            lastmod_val = "".join(lastmod_buf).strip() or None
            if loc_val:
                raw_items.append((loc_val, lastmod_val))
            in_url = False
            active_field = None

    parser = expat.ParserCreate(namespace_separator=" ")
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.StartDoctypeDeclHandler = _on_doctype
    parser.EntityDeclHandler = _on_entity
    parser.StartElementHandler = _on_start
    parser.CharacterDataHandler = _on_char
    parser.EndElementHandler = _on_end

    try:
        parser.Parse(xml_bytes, True)
    except expat.ExpatError as exc:
        raise FetchError(f"Invalid XML sitemap for {feed.name!r}: {exc}") from exc

    fallback_now = datetime.now(UTC)
    dated_candidates: list[tuple[int, datetime, FeedEntry]] = []
    undated_candidates: list[FeedEntry] = []
    seen_urls: set[str] = set()

    for idx, (loc_url, lastmod_raw) in enumerate(raw_items):
        if feed.url_prefix is not None and not _matches_url_prefix(loc_url, feed.url_prefix):
            continue

        parsed_dt = _parse_iso_datetime(lastmod_raw)
        try:
            entry = FeedEntry(
                url=loc_url,
                title=_title_from_url_slug(loc_url),
                summary="",
                published_at=parsed_dt or fallback_now,
                source_name=feed.name,
                source_tier=feed.tier,
            )
        except ValidationError:
            continue

        canonical = canonicalize_url(entry.url)
        if canonical in seen_urls:
            continue
        seen_urls.add(canonical)

        if parsed_dt is not None:
            dated_candidates.append((idx, parsed_dt, entry))
        else:
            undated_candidates.append(entry)

    dated_candidates.sort(key=lambda item: (-item[1].timestamp(), item[0]))
    ordered = [item[2] for item in dated_candidates] + undated_candidates
    return tuple(ordered[:max_entries])


class _AnchorLinkExtractor(HTMLParser):
    """Generic stdlib HTML parser extracting ``<a href>`` links and visible anchor text."""

    def __init__(self, *, max_links: int = MAX_HTML_LINKS) -> None:
        super().__init__(convert_charrefs=True)
        self._max_links = max_links
        self._ignored_depth = 0
        self._current_href: str | None = None
        self._text_parts: list[str] = []
        self.links: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lower = tag.lower()
        if lower in {"script", "style"}:
            self._ignored_depth += 1
            return
        if lower == "a" and self._ignored_depth == 0 and len(self.links) < self._max_links:
            attr_map = dict(attrs)
            href = attr_map.get("href")
            if isinstance(href, str) and href.strip():
                self._current_href = href.strip()
                self._text_parts = []

    def handle_data(self, data: str) -> None:
        if self._ignored_depth == 0 and self._current_href is not None:
            self._text_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        lower = tag.lower()
        if lower in {"script", "style"} and self._ignored_depth > 0:
            self._ignored_depth -= 1
            return
        if lower == "a" and self._current_href is not None:
            self.links.append((self._current_href, "".join(self._text_parts)))
            self._current_href = None
            self._text_parts = []


def parse_html_index_entries(
    html_bytes: bytes,
    feed: SourceFeedConfig,
    *,
    base_url: str | None = None,
    max_entries: int = MAX_FEED_ENTRIES,
) -> tuple[FeedEntry, ...]:
    """Extract same-origin prefix-filtered links from a blog HTML index page.

    Resolves relative links strictly against ``base_url`` (or ``feed.url``), requires a configured
    same-origin ``feed.url_prefix``, strips URI fragments, excludes index URLs themselves, and
    deduplicates canonical URLs cleanly.

    Args:
        html_bytes: Raw HTML bytes of the index listing page.
        feed: Source feed configuration specifying ``url`` and required same-origin ``url_prefix``.
        base_url: Final response URL used for relative link resolution (defaults to ``feed.url``).
        max_entries: Maximum number of entries returned.

    Returns:
        Deduplicated tuple of validated :class:`FeedEntry` items.

    Raises:
        FetchError: If ``max_entries < 1`` or ``feed.url_prefix`` is missing/cross-origin.
    """
    if max_entries < 1:
        raise FetchError("max_entries must be >= 1")
    if feed.url_prefix is None or not _is_same_origin(feed.url, feed.url_prefix):
        raise FetchError(
            f"HTML index discovery for {feed.name!r} requires an explicit same-origin url_prefix."
        )

    effective_base = base_url or feed.url
    parser = _AnchorLinkExtractor()
    parser.feed(html_bytes.decode("utf-8", errors="replace"))
    parser.close()

    excluded_canonicals = {
        canonicalize_url(feed.url),
        canonicalize_url(effective_base),
        canonicalize_url(feed.url_prefix),
    }

    now = datetime.now(UTC)
    results: list[FeedEntry] = []
    seen_urls: set[str] = set()

    for href, anchor_text in parser.links:
        if len(results) >= max_entries:
            break
        joined = urljoin(effective_base, href)
        defragged, _ = urldefrag(joined)

        parsed_scheme = urlparse(defragged).scheme.lower()
        if parsed_scheme not in {"http", "https"}:
            continue
        if not _matches_url_prefix(defragged, feed.url_prefix):
            continue

        canonical = canonicalize_url(defragged)
        if canonical in excluded_canonicals or canonical in seen_urls:
            continue

        try:
            entry = FeedEntry(
                url=defragged,
                title=_clean_anchor_title(anchor_text, defragged),
                summary="",
                published_at=now,
                source_name=feed.name,
                source_tier=feed.tier,
            )
        except ValidationError:
            continue

        seen_urls.add(canonical)
        results.append(entry)

    return tuple(results)


def _looks_like_html(body_bytes: bytes, content_type: str) -> bool:
    """Heuristically identify HTML responses from MIME type or leading document signature."""
    media_type = content_type.lower().split(";", 1)[0].strip()
    if media_type in _HTML_CONTENT_TYPES:
        return True
    prefix = body_bytes.lstrip()[:64].lower()
    return prefix.startswith((b"<!doctype html", b"<html"))


def discover_feed_entries(
    body_bytes: bytes,
    feed: SourceFeedConfig,
    *,
    base_url: str | None = None,
    content_type: str = "",
    max_entries: int = MAX_FEED_ENTRIES,
) -> tuple[FeedEntry, ...]:
    """Discover candidate :class:`FeedEntry` items according to ``feed.kind``.

    Dispatches explicitly to RSS/Atom, XML sitemap, or generic same-origin HTML index parsing;
    in ``FeedKind.AUTO`` mode, tries RSS/Atom -> XML sitemap -> prefix-filtered HTML index.

    Args:
        body_bytes: Raw fetched bytes from the source endpoint.
        feed: Source configuration specifying ``kind`` and optional ``url_prefix``.
        base_url: Final fetched URL used for resolving relative links on HTML index pages.
        content_type: HTTP response Content-Type header value.
        max_entries: Maximum entries to discover per source.

    Returns:
        Deduplicated tuple of :class:`FeedEntry` items.

    Raises:
        FetchError: If XML policy (DOCTYPE/ENTITY), invalid format, or invalid limits occur.
    """
    if feed.kind == FeedKind.RSS:
        return parse_feed_entries(body_bytes, feed, max_entries=max_entries)
    if feed.kind == FeedKind.SITEMAP:
        return parse_sitemap_entries(body_bytes, feed, max_entries=max_entries)
    if feed.kind == FeedKind.HTML_INDEX:
        return parse_html_index_entries(
            body_bytes,
            feed,
            base_url=base_url,
            max_entries=max_entries,
        )

    # FeedKind.AUTO fallback chain: HTML index when MIME/signature is HTML; else RSS -> sitemap.
    has_safe_html_prefix = feed.url_prefix is not None and _is_same_origin(
        feed.url, feed.url_prefix
    )
    if _looks_like_html(body_bytes, content_type):
        if has_safe_html_prefix:
            return parse_html_index_entries(
                body_bytes,
                feed,
                base_url=base_url,
                max_entries=max_entries,
            )
        return ()

    _reject_xml_xxe(body_bytes, feed.name)

    rss_entries = parse_feed_entries(body_bytes, feed, max_entries=max_entries)
    if rss_entries:
        return rss_entries

    try:
        sitemap_entries = parse_sitemap_entries(body_bytes, feed, max_entries=max_entries)
        if sitemap_entries:
            return sitemap_entries
    except _XmlPolicyError:
        raise
    except FetchError:
        # Malformed XML fallback falls through cleanly to guarded HTML index check below.
        pass

    if has_safe_html_prefix:
        return parse_html_index_entries(
            body_bytes,
            feed,
            base_url=base_url,
            max_entries=max_entries,
        )
    return ()


def poll_feed_items(
    feeds: Sequence[SourceFeedConfig],
    *,
    fetcher: SafeHttpFetcher,
    state_store: IngestStateStore | None = None,
    max_entries_per_feed: int = MAX_FEED_ENTRIES,
    mark_seen: bool = False,
) -> tuple[PolledArticle, ...]:
    """Poll enabled source endpoints and fetch new or updated articles securely.

    By default (``mark_seen=False``), newly discovered or modified articles are NOT marked seen in
    ``state_store`` until the downstream pipeline finishes processing them, preventing transient
    extraction failures from permanently skipping advisories. Unchanged articles refresh HTTP
    validators (``ETag`` / ``Last-Modified``) immediately.

    Args:
        feeds: Sequence of allowlisted :class:`SourceFeedConfig` entries.
        fetcher: SSRF-hardened :class:`SafeHttpFetcher` instance.
        state_store: Optional :class:`IngestStateStore` for ``304`` and edit-hash deduplication.
        max_entries_per_feed: Maximum entries inspected per feed poll.
        mark_seen: When ``True``, immediately mark newly discovered/edited articles seen.

    Returns:
        Tuple of :class:`PolledArticle` payloads carrying normalized articles and validators.
    """
    polled: list[PolledArticle] = []

    for feed in feeds:
        if not feed.enabled:
            continue

        feed_resp = fetcher.fetch_bytes(feed.url)
        if feed_resp.not_modified:
            continue

        entries = discover_feed_entries(
            feed_resp.body,
            feed,
            base_url=feed_resp.final_url,
            content_type=feed_resp.content_type,
            max_entries=max_entries_per_feed,
        )
        for entry in entries:
            cond_headers = (
                state_store.conditional_headers(entry.url) if state_store is not None else None
            )
            article, resp = fetcher.fetch_article(
                entry.url,
                source_name=feed.name,
                source_tier=feed.tier,
                published_at=entry.published_at,
                conditional_headers=cond_headers,
            )
            if article is None:
                continue

            content_sha = compute_content_sha256(article.body)
            if state_store is not None:
                changed = state_store.has_changed(article.url, content_sha)
                if not changed:
                    state_store.mark_seen(
                        article.url,
                        content_sha,
                        etag=resp.etag,
                        last_modified=resp.last_modified,
                    )
                    continue
                if mark_seen:
                    state_store.mark_seen(
                        article.url,
                        content_sha,
                        etag=resp.etag,
                        last_modified=resp.last_modified,
                    )

            polled.append(
                PolledArticle(
                    article=article,
                    content_sha256=content_sha,
                    etag=resp.etag,
                    last_modified=resp.last_modified,
                )
            )

    return tuple(polled)


def poll_feeds(
    feeds: Sequence[SourceFeedConfig],
    *,
    fetcher: SafeHttpFetcher,
    state_store: IngestStateStore | None = None,
    max_entries_per_feed: int = MAX_FEED_ENTRIES,
    mark_seen: bool = False,
) -> tuple[RawArticle, ...]:
    """Poll enabled feeds and return newly discovered or updated :class:`RawArticle` objects.

    Args:
        feeds: Sequence of allowlisted :class:`SourceFeedConfig` entries.
        fetcher: SSRF-hardened :class:`SafeHttpFetcher` instance.
        state_store: Optional :class:`IngestStateStore` for ``304`` and edit-hash deduplication.
        max_entries_per_feed: Maximum entries inspected per feed poll.
        mark_seen: Whether to record unseen/changed articles immediately in ``state_store``.

    Returns:
        Tuple of newly discovered or content-modified :class:`RawArticle` objects.
    """
    polled = poll_feed_items(
        feeds,
        fetcher=fetcher,
        state_store=state_store,
        max_entries_per_feed=max_entries_per_feed,
        mark_seen=mark_seen,
    )
    return tuple(item.article for item in polled)
