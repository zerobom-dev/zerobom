"""Shared human-in-the-loop triage decision handler for CLI, HTTP, and Socket Mode."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Mapping, Sequence
from contextlib import ExitStack
from typing import Any, Literal

from zerobom.backends import InventoryBackend, match_advisory_with_backend
from zerobom.models import (
    CredibilityReport,
    MatchResult,
    OsvAdvisory,
    PipelineOutcome,
    RoutingDecision,
    StrictModel,
)
from zerobom.outputs.slack import SlackNotifier, build_slack_triage_decision_payload
from zerobom.outputs.webhook import WebhookNotifier
from zerobom.triage.store import (
    TriageError,
    TriageNotFoundError,
    TriageQueueStore,
    TriageRecord,
    TriageStatus,
    validate_triage_id,
)

TriageNotifier = WebhookNotifier | SlackNotifier


class TriageActionResult(StrictModel):
    """Result of executing an approve or reject triage decision."""

    record: TriageRecord
    matches: tuple[MatchResult, ...] = ()
    already_decided: bool = False
    alert_sent: bool = False


class SlackInteractionRequest(StrictModel):
    """Validated interactive Slack Block Kit button callback action."""

    action_id: Literal["zerobom_triage_approve", "zerobom_triage_reject"]
    triage_id: str
    actor: str
    response_url: str | None = None


def parse_slack_interaction_payload(payload: Mapping[str, Any]) -> SlackInteractionRequest:
    """Parse and strictly validate a Slack ``block_actions`` interaction JSON payload.

    Args:
        payload: Decoded JSON mapping extracted from Slack's ``payload=...`` callback form.

    Returns:
        Validated :class:`SlackInteractionRequest`.

    Raises:
        TriageError: If payload type, action ID, triage value, actor, or URL fail validation.
    """
    if payload.get("type") != "block_actions":
        raise TriageError(f"Unsupported Slack interaction payload type: {payload.get('type')!r}.")

    actions = payload.get("actions")
    if not isinstance(actions, list) or not actions or not isinstance(actions[0], Mapping):
        raise TriageError("Slack interaction payload missing valid 'actions[0]' object.")

    first_action = actions[0]
    raw_action_id = first_action.get("action_id")
    if raw_action_id not in ("zerobom_triage_approve", "zerobom_triage_reject"):
        raise TriageError(f"Unsupported Slack triage action_id: {raw_action_id!r}.")

    triage_id = validate_triage_id(first_action.get("value"))

    raw_user = payload.get("user")
    actor = "slack-user"
    if isinstance(raw_user, Mapping):
        for key in ("username", "name", "id"):
            candidate = raw_user.get(key)
            if isinstance(candidate, str) and candidate.strip():
                cleaned = "".join(
                    ch for ch in candidate if ord(ch) >= 32 and ord(ch) != 127
                ).strip()
                if cleaned:
                    actor = cleaned[:128]
                    break

    raw_resp_url = payload.get("response_url")
    response_url: str | None = None
    if raw_resp_url is not None:
        if not isinstance(raw_resp_url, str) or any(
            ord(ch) < 32 or ord(ch) == 127 for ch in raw_resp_url
        ):
            raise TriageError("Invalid Slack interaction response_url.")
        stripped_url = raw_resp_url.strip()
        if stripped_url:
            response_url = stripped_url

    action_literal: Literal["zerobom_triage_approve", "zerobom_triage_reject"] = (
        "zerobom_triage_approve"
        if raw_action_id == "zerobom_triage_approve"
        else "zerobom_triage_reject"
    )
    return SlackInteractionRequest(
        action_id=action_literal,
        triage_id=triage_id,
        actor=actor,
        response_url=response_url,
    )


class TriageActionHandler:
    """Shared deterministic execution engine for CLI, HTTP webhook, and Socket Mode actions."""

    def __init__(
        self,
        store: TriageQueueStore,
        *,
        backend_factory: Callable[[], InventoryBackend | None] | None = None,
        alert_notifiers: Sequence[TriageNotifier] = (),
    ) -> None:
        """Initialize the shared triage decision engine.

        Args:
            store: SQLite triage queue store.
            backend_factory: Optional callable creating a fresh :class:`InventoryBackend`
                when approving an advisory (``close()`` is invoked automatically).
            alert_notifiers: Outbound notifiers notified only when an approved item yields hits.
        """
        self._store = store
        self._backend_factory = backend_factory
        self._alert_notifiers = tuple(alert_notifiers)
        self._locks_guard = threading.Lock()
        self._item_locks: dict[str, threading.Lock] = {}

    def _lock_for_id(self, triage_id: str) -> threading.Lock:
        """Return a per-triage-ID lock to serialize duplicate or concurrent callbacks."""
        with self._locks_guard:
            lock = self._item_locks.get(triage_id)
            if lock is None:
                if len(self._item_locks) >= 4096:
                    stale = [k for k, v in self._item_locks.items() if not v.locked()]
                    for k in stale[:2048]:
                        self._item_locks.pop(k, None)
                lock = threading.Lock()
                self._item_locks[triage_id] = lock
            return lock

    def approve(
        self,
        triage_id: str,
        *,
        actor: str,
        note: str | None = None,
    ) -> TriageActionResult:
        """Approve a ``PENDING`` advisory, scan inventory deterministically, and alert on hits."""
        cleaned_id = validate_triage_id(triage_id)
        with self._lock_for_id(cleaned_id):
            record = self._store.get(cleaned_id)
            if record is None:
                raise TriageNotFoundError(f"Triage item {cleaned_id!r} does not exist.")

            if record.status != TriageStatus.PENDING:
                return TriageActionResult(
                    record=record,
                    already_decided=True,
                )

            try:
                osv = OsvAdvisory.model_validate_json(record.osv_json)
                credibility = CredibilityReport.model_validate_json(record.credibility_json)
            except Exception as exc:
                raise TriageError(
                    f"Corrupted OSV/credibility payload stored for triage item "
                    f"{record.triage_id!r}: {exc}"
                ) from exc

            matches: tuple[MatchResult, ...] = ()
            if self._backend_factory is not None:
                with ExitStack() as stack:
                    backend = self._backend_factory()
                    if backend is not None:
                        close_fn = getattr(backend, "close", None)
                        if callable(close_fn):
                            stack.callback(close_fn)
                        matches = match_advisory_with_backend(osv, backend, only_vulnerable=True)

            matches_json = (
                json.dumps([m.model_dump(mode="json") for m in matches], sort_keys=True)
                if matches
                else "[]"
            )

            updated, transitioned = self._store.transition_status(
                record.triage_id,
                new_status=TriageStatus.APPROVED,
                actor=actor,
                note=note,
                match_count=len(matches),
                matches_json=matches_json,
            )
            if not transitioned:
                return TriageActionResult(record=updated, already_decided=True)

            alert_sent = False
            if matches and self._alert_notifiers:
                approved_outcome = PipelineOutcome(
                    credibility=credibility.model_copy(update={"routing": RoutingDecision.AUTO}),
                    osv=osv,
                    matches=matches,
                )
                for notifier in self._alert_notifiers:
                    delivery = notifier.send_outcome(approved_outcome)
                    if delivery.delivered:
                        alert_sent = True

            return TriageActionResult(
                record=updated,
                matches=matches,
                already_decided=False,
                alert_sent=alert_sent,
            )

    def reject(
        self,
        triage_id: str,
        *,
        actor: str,
        note: str | None = None,
    ) -> TriageActionResult:
        """Reject a ``PENDING`` advisory without scanning or alerting."""
        cleaned_id = validate_triage_id(triage_id)
        with self._lock_for_id(cleaned_id):
            record = self._store.get(cleaned_id)
            if record is None:
                raise TriageNotFoundError(f"Triage item {cleaned_id!r} does not exist.")
            if record.status != TriageStatus.PENDING:
                return TriageActionResult(record=record, already_decided=True)

            updated, transitioned = self._store.transition_status(
                record.triage_id,
                new_status=TriageStatus.REJECTED,
                actor=actor,
                note=note,
            )
            return TriageActionResult(
                record=updated,
                already_decided=not transitioned,
            )

    def execute_slack_interaction(
        self,
        request: SlackInteractionRequest,
    ) -> tuple[TriageActionResult, dict[str, Any]]:
        """Dispatch a Slack interactive callback and return a replacement Block Kit body."""
        if request.action_id == "zerobom_triage_approve":
            result = self.approve(request.triage_id, actor=request.actor)
        else:
            result = self.reject(request.triage_id, actor=request.actor)

        payload = build_slack_triage_decision_payload(
            advisory_id=result.record.advisory_id,
            status=result.record.status.value,
            actor=result.record.decided_by or request.actor,
            match_count=result.record.last_match_count or len(result.matches),
            already_decided=result.already_decided,
            note=result.record.decision_note,
        )
        return result, payload
