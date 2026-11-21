"""Parameterized SQLite queue store for persistent ``TRIAGE`` advisory workflows."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from zerobom.models import PipelineOutcome, RoutingDecision, StrictModel
from zerobom.outputs.webhook import extract_verified_quotes

_TRIAGE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_SAFE_CHANNEL_RE = re.compile(r"^[a-z0-9_.-]{1,64}$")


class TriageError(RuntimeError):
    """Base error for triage queue persistence, validation, and action failures."""


class TriageNotFoundError(TriageError):
    """Raised when a requested triage item ID does not exist in the queue store."""


class TriageStatus(StrEnum):
    """Lifecycle states of a queued human-triage advisory."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class TriageRecord(StrictModel):
    """Persistent triage queue item capturing compiled OSV JSON and human audit state."""

    triage_id: str
    advisory_id: str
    article_url: str
    source_name: str
    title: str
    composite_score: float
    status: TriageStatus
    osv_json: str
    credibility_json: str
    evidence_quote: str | None = None
    notification_digest: str | None = None
    notified_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    decided_at: datetime | None = None
    decided_by: str | None = None
    decision_note: str | None = None
    last_match_count: int | None = None
    last_matches_json: str | None = None


def validate_triage_id(triage_id: Any) -> str:
    """Validate an untrusted triage identifier before SQL lookup or CLI/Slack dispatch."""
    if not isinstance(triage_id, str):
        raise TriageError("Triage ID must be a string.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in triage_id):
        raise TriageError("Triage ID must not contain control characters.")
    cleaned = triage_id.strip()
    if ".." in cleaned or not _TRIAGE_ID_RE.fullmatch(cleaned):
        raise TriageError(
            f"Invalid triage ID {triage_id!r}; expected 1-128 chars in [A-Za-z0-9._-] without '..'."
        )
    return cleaned


def _sanitize_short_text(value: str | None, *, max_length: int = 256, fallback: str = "") -> str:
    """Strip control characters and bound actor/note text stored in audit fields."""
    if not isinstance(value, str):
        return fallback
    cleaned = "".join(ch for ch in value if ch == " " or (ord(ch) >= 32 and ord(ch) != 127)).strip()
    if len(cleaned) > max_length:
        return cleaned[:max_length]
    return cleaned or fallback


def _row_to_record(row: tuple[Any, ...]) -> TriageRecord:
    """Hydrate a SQLite row tuple into an immutable :class:`TriageRecord`."""
    return TriageRecord(
        triage_id=str(row[0]),
        advisory_id=str(row[1]),
        article_url=str(row[2]),
        source_name=str(row[3]),
        title=str(row[4]),
        composite_score=float(row[5]),
        status=TriageStatus(str(row[6])),
        osv_json=str(row[7]),
        credibility_json=str(row[8]),
        evidence_quote=str(row[9]) if row[9] is not None else None,
        notification_digest=str(row[10]) if row[10] is not None else None,
        notified_at=datetime.fromisoformat(str(row[11])) if row[11] is not None else None,
        created_at=datetime.fromisoformat(str(row[12])),
        updated_at=datetime.fromisoformat(str(row[13])),
        decided_at=datetime.fromisoformat(str(row[14])) if row[14] is not None else None,
        decided_by=str(row[15]) if row[15] is not None else None,
        decision_note=str(row[16]) if row[16] is not None else None,
        last_match_count=int(row[17]) if row[17] is not None else None,
        last_matches_json=str(row[18]) if row[18] is not None else None,
    )


def _fetch_record(conn: sqlite3.Connection, triage_id: str) -> TriageRecord | None:
    """Fetch one ``triage_items`` row using static parameterized SQL."""
    row = conn.execute(
        """
        SELECT triage_id, advisory_id, article_url, source_name, title, composite_score,
               status, osv_json, credibility_json, evidence_quote, notification_digest,
               notified_at, created_at, updated_at, decided_at, decided_by, decision_note,
               last_match_count, last_matches_json
        FROM triage_items
        WHERE triage_id = ?
        """,
        (triage_id,),
    ).fetchone()
    return _row_to_record(row) if row is not None else None


class TriageQueueStore:
    """SQLite-backed human triage queue with atomic state transitions and alert dedup."""

    def __init__(self, db_path: Path | str) -> None:
        """Initialize the triage SQLite database and ensure WAL/schema setup."""
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @property
    def db_path(self) -> Path:
        """Filesystem path backing this SQLite triage queue."""
        return self._db_path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=5.0)
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.execute("PRAGMA journal_mode = WAL")
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS triage_items (
                        triage_id TEXT PRIMARY KEY,
                        advisory_id TEXT NOT NULL,
                        article_url TEXT NOT NULL,
                        source_name TEXT NOT NULL,
                        title TEXT NOT NULL,
                        composite_score REAL NOT NULL,
                        status TEXT NOT NULL,
                        osv_json TEXT NOT NULL,
                        credibility_json TEXT NOT NULL,
                        evidence_quote TEXT,
                        notification_digest TEXT,
                        notified_at TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        decided_at TEXT,
                        decided_by TEXT,
                        decision_note TEXT,
                        last_match_count INTEGER,
                        last_matches_json TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS triage_notifications (
                        triage_id TEXT NOT NULL,
                        channel TEXT NOT NULL,
                        digest TEXT NOT NULL,
                        notified_at TEXT NOT NULL,
                        PRIMARY KEY (triage_id, channel)
                    )
                    """
                )
        finally:
            conn.close()

    def enqueue_outcome(self, outcome: PipelineOutcome) -> TriageRecord | None:
        """Enqueue a compiled ``TRIAGE`` outcome into the persistent queue, if eligible.

        Already-decided records are preserved intact rather than silently reverted to pending.
        """
        if (
            outcome.osv is None
            or outcome.credibility is None
            or outcome.credibility.routing != RoutingDecision.TRIAGE
        ):
            return None

        triage_id = validate_triage_id(outcome.osv.id)
        now_iso = datetime.now(UTC).isoformat()
        osv_json = json.dumps(outcome.osv.to_osv_dict(), sort_keys=True)
        credibility_json = outcome.credibility.model_dump_json()

        quotes = extract_verified_quotes(outcome)
        evidence_quote = quotes[0] if quotes else None

        zb_meta = outcome.osv.database_specific.get("zerobom")
        source_name = (
            outcome.article.source_name
            if outcome.article is not None
            else (
                str(zb_meta.get("source_name"))
                if isinstance(zb_meta, Mapping) and zb_meta.get("source_name")
                else "Unknown"
            )
        )
        title = outcome.article.title if outcome.article is not None else outcome.osv.summary

        conn = self._connect()
        try:
            with conn:
                current_record = _fetch_record(conn, triage_id)
                if current_record is not None:
                    if current_record.status != TriageStatus.PENDING:
                        return current_record
                    conn.execute(
                        """
                        UPDATE triage_items
                        SET article_url = ?, source_name = ?, title = ?, composite_score = ?,
                            osv_json = ?, credibility_json = ?, evidence_quote = ?, updated_at = ?
                        WHERE triage_id = ? AND status = ?
                        """,
                        (
                            outcome.credibility.article_url,
                            _sanitize_short_text(source_name, max_length=200, fallback="Unknown"),
                            _sanitize_short_text(title, max_length=500, fallback=outcome.osv.id),
                            float(outcome.credibility.composite_score),
                            osv_json,
                            credibility_json,
                            evidence_quote,
                            now_iso,
                            triage_id,
                            TriageStatus.PENDING.value,
                        ),
                    )
                else:
                    conn.execute(
                        """
                        INSERT INTO triage_items (
                            triage_id, advisory_id, article_url, source_name, title,
                            composite_score, status, osv_json, credibility_json, evidence_quote,
                            created_at, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            triage_id,
                            outcome.osv.id,
                            outcome.credibility.article_url,
                            _sanitize_short_text(source_name, max_length=200, fallback="Unknown"),
                            _sanitize_short_text(title, max_length=500, fallback=outcome.osv.id),
                            float(outcome.credibility.composite_score),
                            TriageStatus.PENDING.value,
                            osv_json,
                            credibility_json,
                            evidence_quote,
                            now_iso,
                            now_iso,
                        ),
                    )
                persisted = _fetch_record(conn, triage_id)
                if persisted is None:
                    raise TriageError(f"Failed to persist triage item {triage_id!r}.")
                return persisted
        finally:
            conn.close()

    def get(self, triage_id: str) -> TriageRecord | None:
        """Retrieve a single :class:`TriageRecord` by ID, or ``None`` if not present."""
        cleaned_id = validate_triage_id(triage_id)
        conn = self._connect()
        try:
            return _fetch_record(conn, cleaned_id)
        finally:
            conn.close()

    def list_items(
        self,
        *,
        status: TriageStatus | None = None,
        limit: int = 100,
    ) -> tuple[TriageRecord, ...]:
        """List triage records ordered newest-first, optionally filtered by status."""
        if isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise TriageError("list_items 'limit' must be between 1 and 1000.")
        conn = self._connect()
        try:
            if status is not None:
                rows = conn.execute(
                    """
                    SELECT triage_id, advisory_id, article_url, source_name, title,
                           composite_score, status, osv_json, credibility_json, evidence_quote,
                           notification_digest, notified_at, created_at, updated_at, decided_at,
                           decided_by, decision_note, last_match_count, last_matches_json
                    FROM triage_items
                    WHERE status = ?
                    ORDER BY created_at DESC LIMIT ?
                    """,
                    (status.value, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT triage_id, advisory_id, article_url, source_name, title,
                           composite_score, status, osv_json, credibility_json, evidence_quote,
                           notification_digest, notified_at, created_at, updated_at, decided_at,
                           decided_by, decision_note, last_match_count, last_matches_json
                    FROM triage_items
                    ORDER BY created_at DESC LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            return tuple(_row_to_record(r) for r in rows)
        finally:
            conn.close()

    def should_notify(self, triage_id: str, digest: str, *, channel: str = "default") -> bool:
        """Return ``True`` if ``(triage_id, channel)`` has not already sent ``digest``."""
        cleaned_id = validate_triage_id(triage_id)
        cleaned_channel = channel.strip().lower()
        if not _SAFE_CHANNEL_RE.fullmatch(cleaned_channel):
            raise TriageError(f"Invalid notification channel name: {channel!r}.")
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT digest FROM triage_notifications WHERE triage_id = ? AND channel = ?",
                (cleaned_id, cleaned_channel),
            ).fetchone()
            if row is not None:
                return str(row[0]) != digest
            has_any_channel = conn.execute(
                "SELECT 1 FROM triage_notifications WHERE triage_id = ? LIMIT 1",
                (cleaned_id,),
            ).fetchone()
            if has_any_channel is not None:
                # Avoid cross-suppressing when other channels have entries, but none for this one.
                return True
            item_row = conn.execute(
                "SELECT notification_digest FROM triage_items WHERE triage_id = ?",
                (cleaned_id,),
            ).fetchone()
            if item_row is not None and item_row[0] is not None:
                return str(item_row[0]) != digest
            return True
        finally:
            conn.close()

    def mark_notified(self, triage_id: str, digest: str, *, channel: str = "default") -> None:
        """Record that ``digest`` was delivered for ``(triage_id, channel)``."""
        cleaned_id = validate_triage_id(triage_id)
        cleaned_channel = channel.strip().lower()
        if not _SAFE_CHANNEL_RE.fullmatch(cleaned_channel):
            raise TriageError(f"Invalid notification channel name: {channel!r}.")
        now_iso = datetime.now(UTC).isoformat()
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO triage_notifications (triage_id, channel, digest, notified_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(triage_id, channel) DO UPDATE SET
                        digest = excluded.digest,
                        notified_at = excluded.notified_at
                    """,
                    (cleaned_id, cleaned_channel, digest, now_iso),
                )
                conn.execute(
                    """
                    UPDATE triage_items
                    SET notification_digest = ?, notified_at = ?, updated_at = ?
                    WHERE triage_id = ?
                    """,
                    (digest, now_iso, now_iso, cleaned_id),
                )
        finally:
            conn.close()

    def transition_status(
        self,
        triage_id: str,
        *,
        new_status: TriageStatus,
        actor: str,
        note: str | None = None,
        match_count: int | None = None,
        matches_json: str | None = None,
    ) -> tuple[TriageRecord, bool]:
        """Atomically transition a ``PENDING`` item to ``APPROVED`` or ``REJECTED``.

        Returns:
            ``(record, True)`` if this caller won the transition; ``(existing, False)`` if the
            item had already transitioned previously (preventing duplicate concurrent alerts).
        """
        if new_status == TriageStatus.PENDING:
            raise TriageError("Cannot transition a triage item back to 'pending'.")

        cleaned_id = validate_triage_id(triage_id)
        safe_actor = _sanitize_short_text(actor, max_length=128, fallback="unknown")
        safe_note = _sanitize_short_text(note, max_length=512, fallback="") or None
        now_iso = datetime.now(UTC).isoformat()

        conn = self._connect()
        try:
            with conn:
                cursor = conn.execute(
                    """
                    UPDATE triage_items
                    SET status = ?, decided_at = ?, decided_by = ?, decision_note = ?,
                        last_match_count = ?, last_matches_json = ?, updated_at = ?
                    WHERE triage_id = ? AND status = ?
                    """,
                    (
                        new_status.value,
                        now_iso,
                        safe_actor,
                        safe_note,
                        match_count,
                        matches_json,
                        now_iso,
                        cleaned_id,
                        TriageStatus.PENDING.value,
                    ),
                )
                transitioned = cursor.rowcount == 1
                record = _fetch_record(conn, cleaned_id)
                if record is None:
                    raise TriageNotFoundError(f"Triage item {cleaned_id!r} was not found.")
                return record, transitioned
        finally:
            conn.close()
