"""Parameterized SQLite state store for ingestion deduplication and edit detection."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from zerobom.models import ArticleStateRecord, RoutingDecision
from zerobom.verify.osv_compiler import canonicalize_url


class IngestStateStore:
    """SQLite-backed state tracking canonical article hashes and HTTP cache validators.

    Unlike naive URL-only deduplication, storing ``content_sha256`` alongside ``ETag`` and
    ``Last-Modified`` headers allows ``zerobom watch`` to skip unchanged articles cheaply via
    HTTP ``304`` while automatically re-processing live advisories that receive post-publish
    edits (such as newly added fixed versions).
    """

    def __init__(self, db_path: Path | str) -> None:
        """Initialize the SQLite ingestion state store and ensure schema existence.

        Args:
            db_path: Path to the SQLite database file (parent directories created if needed).
        """
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path)

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS article_state (
                        canonical_url TEXT PRIMARY KEY,
                        content_sha256 TEXT NOT NULL,
                        etag TEXT,
                        last_modified TEXT,
                        last_seen_at TEXT NOT NULL,
                        advisory_id TEXT,
                        routing TEXT
                    )
                    """
                )
        finally:
            conn.close()

    def get(self, url: str) -> ArticleStateRecord | None:
        """Retrieve the persisted :class:`ArticleStateRecord` for a URL, if recorded."""
        canonical = canonicalize_url(url)
        conn = self._connect()
        try:
            # Parameterized SQL (?) prevents injection regardless of URL query strings.
            row = conn.execute(
                """
                SELECT canonical_url, content_sha256, etag, last_modified,
                       last_seen_at, advisory_id, routing
                FROM article_state
                WHERE canonical_url = ?
                """,
                (canonical,),
            ).fetchone()
            if row is None:
                return None

            raw_routing = row[6]
            routing = RoutingDecision(str(raw_routing)) if raw_routing is not None else None
            return ArticleStateRecord(
                canonical_url=str(row[0]),
                content_sha256=str(row[1]),
                etag=str(row[2]) if row[2] is not None else None,
                last_modified=str(row[3]) if row[3] is not None else None,
                last_seen_at=datetime.fromisoformat(str(row[4])),
                advisory_id=str(row[5]) if row[5] is not None else None,
                routing=routing,
            )
        finally:
            conn.close()

    def has_changed(self, url: str, content_sha256: str) -> bool:
        """Return True if ``url`` is unseen or its normalized ``content_sha256`` changed."""
        existing = self.get(url)
        if existing is None:
            return True
        return existing.content_sha256 != content_sha256.strip().lower()

    def conditional_headers(self, url: str) -> dict[str, str]:
        """Build HTTP conditional request headers from persisted ``ETag`` / ``Last-Modified``."""
        existing = self.get(url)
        if existing is None:
            return {}
        headers: dict[str, str] = {}
        if existing.etag:
            headers["If-None-Match"] = existing.etag
        if existing.last_modified:
            headers["If-Modified-Since"] = existing.last_modified
        return headers

    def upsert(self, record: ArticleStateRecord) -> None:
        """Insert or update an :class:`ArticleStateRecord` using parameterized SQL."""
        canonical = canonicalize_url(record.canonical_url)
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO article_state (
                        canonical_url, content_sha256, etag, last_modified,
                        last_seen_at, advisory_id, routing
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(canonical_url) DO UPDATE SET
                        content_sha256 = excluded.content_sha256,
                        etag = COALESCE(excluded.etag, article_state.etag),
                        last_modified = COALESCE(
                            excluded.last_modified, article_state.last_modified
                        ),
                        last_seen_at = excluded.last_seen_at,
                        advisory_id = COALESCE(excluded.advisory_id, article_state.advisory_id),
                        routing = COALESCE(excluded.routing, article_state.routing)
                    """,
                    (
                        canonical,
                        record.content_sha256,
                        record.etag,
                        record.last_modified,
                        record.last_seen_at.isoformat(),
                        record.advisory_id,
                        record.routing.value if record.routing is not None else None,
                    ),
                )
        finally:
            conn.close()

    def mark_seen(
        self,
        url: str,
        content_sha256: str,
        *,
        etag: str | None = None,
        last_modified: str | None = None,
        advisory_id: str | None = None,
        routing: RoutingDecision | None = None,
        seen_at: datetime | None = None,
    ) -> ArticleStateRecord:
        """Convenience wrapper to build and persist an :class:`ArticleStateRecord`."""
        record = ArticleStateRecord(
            canonical_url=canonicalize_url(url),
            content_sha256=content_sha256,
            etag=etag,
            last_modified=last_modified,
            last_seen_at=seen_at or datetime.now(UTC),
            advisory_id=advisory_id,
            routing=routing,
        )
        self.upsert(record)
        return record

    def count(self) -> int:
        """Return total number of tracked canonical article URLs."""
        conn = self._connect()
        try:
            row = conn.execute("SELECT COUNT(*) FROM article_state").fetchone()
            return int(row[0]) if row is not None else 0
        finally:
            conn.close()
