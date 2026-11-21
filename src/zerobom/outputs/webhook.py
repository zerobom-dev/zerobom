"""SSRF-hardened generic outbound JSON webhook alerting with HMAC-SHA256 signatures."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx

from zerobom.backends import BackendError
from zerobom.backends._http import (
    REDIRECT_STATUS_CODES,
    read_bounded_response,
    validate_timeout_seconds,
)
from zerobom.ingest.fetcher import (
    MAX_FETCH_URL_LENGTH,
    DnsResolver,
    default_dns_resolver,
    is_public_ip,
)
from zerobom.models import PipelineOutcome, RoutingDecision, StrictModel

_MAX_WEBHOOK_RESPONSE_BYTES = 64 * 1024
_DEFAULT_WEBHOOK_TIMEOUT_SECONDS = 10.0


class AlertDeliveryError(RuntimeError):
    """Raised when outbound alert validation, signing, or HTTP delivery fails."""


class AlertDeliveryResult(StrictModel):
    """Outcome summary returned for each evaluated outbound alert notification."""

    advisory_id: str | None = None
    event_type: Literal["auto_hit", "triage_review", "skipped"]
    delivered: bool
    status_code: int | None = None
    digest: str | None = None
    reason: str | None = None


def validate_webhook_url(
    url: str,
    *,
    allow_insecure_http: bool = False,
    allow_private_targets: bool = False,
    allowed_hosts: frozenset[str] | None = None,
    dns_resolver: DnsResolver = default_dns_resolver,
) -> str:
    """Validate an outbound webhook/callback URL against scheme, host, and SSRF policies.

    Args:
        url: Candidate webhook or Slack callback URL.
        allow_insecure_http: Explicit opt-in for plain ``http://`` URLs (dev/local only).
        allow_private_targets: Explicit opt-in to skip public-IP checks (internal relays only).
        allowed_hosts: Optional exact lowercase hostname allowlist (e.g. Slack webhook hosts).
        dns_resolver: DNS resolution callable returning IP strings for host/port pairs.

    Returns:
        Normalized trimmed webhook URL.

    Raises:
        AlertDeliveryError: If syntax, scheme, credentials, host allowlist, or IP checks fail.
    """
    if not isinstance(url, str):
        raise AlertDeliveryError("Webhook URL must be a string.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise AlertDeliveryError("Webhook URL must not contain ASCII control characters.")

    cleaned = url.strip()
    if not cleaned or len(cleaned) > MAX_FETCH_URL_LENGTH:
        raise AlertDeliveryError("Webhook URL is empty or exceeds maximum length.")
    if any(ch.isspace() for ch in cleaned):
        raise AlertDeliveryError("Webhook URL must not contain whitespace.")

    parsed = urlsplit(cleaned)
    scheme = parsed.scheme.lower()
    allowed_schemes = {"https", "http"} if allow_insecure_http else {"https"}
    if scheme not in allowed_schemes:
        if scheme == "http" and not allow_insecure_http:
            raise AlertDeliveryError(
                "Webhook URL requires https:// (pass allow_insecure_http=True to permit http://)."
            )
        raise AlertDeliveryError(f"Unsupported webhook URL scheme {parsed.scheme!r}.")

    if parsed.username is not None or parsed.password is not None:
        raise AlertDeliveryError("Webhook URL must not embed credentials.")
    if parsed.fragment:
        raise AlertDeliveryError("Webhook URL must not include a fragment.")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise AlertDeliveryError("Webhook URL must include a valid hostname.")

    if allowed_hosts is not None and hostname not in allowed_hosts:
        raise AlertDeliveryError(
            f"Webhook host {hostname!r} is not in the permitted host allowlist "
            f"{sorted(allowed_hosts)}."
        )

    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise AlertDeliveryError(f"Invalid port in webhook URL: {exc}") from exc

    if not allow_private_targets:
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            if not is_public_ip(hostname):
                raise AlertDeliveryError(
                    f"Blocked non-public webhook literal IP host {hostname!r}."
                )

        try:
            resolved_ips = dns_resolver(hostname, port)
        except Exception as exc:
            raise AlertDeliveryError(
                f"DNS resolution failed for webhook host {hostname!r}: {exc}"
            ) from exc

        if not resolved_ips:
            raise AlertDeliveryError(
                f"DNS resolution returned no IPs for webhook host {hostname!r}."
            )
        for ip_str in resolved_ips:
            if not is_public_ip(ip_str):
                raise AlertDeliveryError(
                    f"Blocked SSRF target: webhook host {hostname!r} resolved to non-public "
                    f"IP {ip_str!r}."
                )

    return cleaned


def sign_webhook_body(body: bytes, secret: str, timestamp: int) -> str:
    """Compute ``sha256=<hex>`` HMAC signature over ``{timestamp}.{body}``."""
    signed_payload = f"{timestamp}.".encode("ascii") + body
    digest = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def classify_alert_event(
    outcome: PipelineOutcome,
) -> Literal["auto_hit", "triage_review"] | None:
    """Determine outbound alerting policy for a :class:`PipelineOutcome`.

    Policy:
    - ``DROP`` -> ``None`` (silent).
    - ``TRIAGE`` -> ``"triage_review"`` when a compiled OSV advisory is present.
    - ``AUTO`` or pure ``scan`` (``credibility is None``) -> ``"auto_hit"`` ONLY when
      at least one vulnerable inventory component matched.
    """
    if outcome.credibility is not None:
        if outcome.credibility.routing == RoutingDecision.DROP:
            return None
        if outcome.credibility.routing == RoutingDecision.TRIAGE:
            return "triage_review" if outcome.osv is not None else None

    if outcome.osv is not None and outcome.vulnerable_matches:
        return "auto_hit"
    return None


def extract_verified_quotes(outcome: PipelineOutcome) -> tuple[str, ...]:
    """Collect deduplicated grounded evidence quotes from verification or match results."""
    seen: set[str] = set()
    quotes: list[str] = []

    if outcome.credibility is not None:
        for claim_res in outcome.credibility.accepted_claims:
            q = claim_res.claim.evidence_quote.strip()
            if q and q not in seen:
                seen.add(q)
                quotes.append(q)

    for match in outcome.vulnerable_matches:
        if match.evidence_quote:
            q = match.evidence_quote.strip()
            if q and q not in seen:
                seen.add(q)
                quotes.append(q)

    return tuple(quotes)


def extract_safe_source_url(outcome: PipelineOutcome) -> str | None:
    """Return the validated ``http``/``https`` advisory reference URL if available."""
    candidates: list[str] = []
    if outcome.article is not None:
        candidates.append(outcome.article.url)
    if outcome.credibility is not None:
        candidates.append(outcome.credibility.article_url)
    if outcome.osv is not None:
        candidates.extend(ref.url for ref in outcome.osv.references)

    for url in candidates:
        scheme = urlsplit(url).scheme.lower()
        if scheme in {"http", "https"}:
            return url
    return None


def build_webhook_payload(
    outcome: PipelineOutcome,
    *,
    event_type: Literal["auto_hit", "triage_review"],
    triage_id: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Build a canonical JSON webhook payload and its deterministic SHA-256 digest.

    Args:
        outcome: Evaluated :class:`PipelineOutcome`.
        event_type: Classified notification category (``"auto_hit"`` or ``"triage_review"``).
        triage_id: Optional persisted triage queue ID included for review workflows.

    Returns:
        Tuple of ``(payload_dict, payload_sha256_hex)``.
    """
    osv = outcome.osv
    credibility = outcome.credibility
    advisory_id = osv.id if osv is not None else "unknown"
    summary = (
        osv.summary
        if osv is not None
        else (outcome.advisory.summary if outcome.advisory is not None else "")
    )

    affected_packages: list[dict[str, str]] = []
    if osv is not None:
        for aff in osv.affected:
            affected_packages.append(
                {
                    "ecosystem": aff.package.ecosystem,
                    "name": aff.package.name,
                    "purl": aff.package.purl,
                }
            )

    matches_list: list[dict[str, Any]] = []
    for match in outcome.vulnerable_matches:
        match_obj: dict[str, Any] = {
            "advisory_id": match.advisory_id,
            "component_purl": match.component_purl,
            "installed_version": match.installed_version,
            "matched_purl": match.matched_purl,
            "ecosystem": match.ecosystem,
            "fixed_versions": list(match.fixed_versions),
            "sbom_source": match.sbom_source,
        }
        if match.asset is not None:
            match_obj["asset"] = {
                "asset_id": match.asset.asset_id,
                "asset_type": match.asset.asset_type,
                "backend": match.asset.backend,
                "scope": match.asset.scope,
                "location": match.asset.location,
            }
        matches_list.append(match_obj)

    if event_type == "triage_review":
        approve_cmd = (
            f"zerobom triage approve {triage_id}"
            if triage_id
            else f"zerobom scan --osv {advisory_id}.osv.json --sbom <path-to-sbom>"
        )
        triage_info: dict[str, Any] | None = {
            "triage_id": triage_id,
            "approve_command": approve_cmd,
            "reject_command": f"zerobom triage reject {triage_id}" if triage_id else None,
        }
    else:
        triage_info = None

    zb_meta = osv.database_specific.get("zerobom") if osv is not None else None
    source_name = (
        outcome.article.source_name
        if outcome.article is not None
        else (zb_meta.get("source_name") if isinstance(zb_meta, Mapping) else None)
    )

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "event": event_type,
        "advisory_id": advisory_id,
        "summary": summary,
        "source_url": extract_safe_source_url(outcome),
        "source_name": source_name,
        "source_tier": credibility.source_tier.value if credibility is not None else None,
        "composite_score": round(credibility.composite_score, 4) if credibility else None,
        "routing": credibility.routing.value if credibility is not None else "scan",
        "affected_packages": affected_packages,
        "evidence_quotes": list(extract_verified_quotes(outcome)),
        "vulnerable_matches": matches_list,
        "triage": triage_info,
    }
    canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(canonical_bytes).hexdigest()
    return payload, digest


def redact_url_for_repr(url: str) -> str:
    """Return ``scheme://host/...`` without revealing secret webhook path tokens or queries."""
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}/..."


def _post_json_webhook(
    client: httpx.Client,
    url: str,
    payload: Mapping[str, Any],
    *,
    headers: Mapping[str, str] | None = None,
    backend_name: str = "webhook",
) -> int:
    """Send a JSON POST without following redirects and check 2xx status."""
    req_headers: dict[str, str] = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        req_headers.update(headers)

    try:
        status, _, body = read_bounded_response(
            client,
            "POST",
            url,
            max_bytes=_MAX_WEBHOOK_RESPONSE_BYTES,
            headers=req_headers,
            json_body=dict(payload),
            backend_name=backend_name,
            redact_url_path=True,
        )
    except Exception as exc:
        raise AlertDeliveryError(
            f"Webhook delivery failed ({type(exc).__name__}) for {redact_url_for_repr(url)}."
        ) from exc

    if status in REDIRECT_STATUS_CODES:
        raise AlertDeliveryError(
            f"Webhook redirect ({status}) refused for {redact_url_for_repr(url)}."
        )
    if not 200 <= status < 300:
        snippet = body[:200].decode("utf-8", errors="replace")
        raise AlertDeliveryError(
            f"Webhook delivery returned HTTP {status} from {redact_url_for_repr(url)}: {snippet}"
        )
    return status


class WebhookNotifier:
    """Stateless SSRF-hardened JSON webhook alert client with optional HMAC signing."""

    def __init__(
        self,
        url: str,
        *,
        signing_secret: str | None = None,
        timeout_seconds: float = _DEFAULT_WEBHOOK_TIMEOUT_SECONDS,
        allow_insecure_http: bool = False,
        allow_private_targets: bool = False,
        allowed_hosts: frozenset[str] | None = None,
        dns_resolver: DnsResolver = default_dns_resolver,
        http_client: httpx.Client | None = None,
    ) -> None:
        """Initialize an SSRF-validated generic webhook alert client."""
        self._url = validate_webhook_url(
            url,
            allow_insecure_http=allow_insecure_http,
            allow_private_targets=allow_private_targets,
            allowed_hosts=allowed_hosts,
            dns_resolver=dns_resolver,
        )
        if signing_secret is not None and (
            any(ord(ch) < 32 or ord(ch) == 127 for ch in signing_secret)
            or not signing_secret.strip()
        ):
            raise AlertDeliveryError(
                "Webhook signing_secret must be non-empty without control chars."
            )
        self._signing_secret = signing_secret
        try:
            self._timeout_seconds = validate_timeout_seconds(timeout_seconds)
        except (BackendError, ValueError) as exc:
            raise AlertDeliveryError(str(exc)) from exc

        self._allow_insecure_http = allow_insecure_http
        self._allow_private_targets = allow_private_targets
        self._allowed_hosts = allowed_hosts
        self._dns_resolver = dns_resolver

        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            self._client = httpx.Client(
                timeout=self._timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            )
            self._owns_client = True

    def close(self) -> None:
        """Close the internally managed HTTP client connection pool."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> WebhookNotifier:
        """Enter context manager returning self."""
        return self

    def __exit__(self, *_: object) -> None:
        """Close managed HTTP client on context exit."""
        self.close()

    def __repr__(self) -> str:
        """Return a redacted summary hiding path tokens and signing secrets."""
        return (
            f"WebhookNotifier(target={redact_url_for_repr(self._url)!r}, "
            f"signed={self._signing_secret is not None})"
        )

    def send_outcome(
        self,
        outcome: PipelineOutcome,
        *,
        triage_id: str | None = None,
        dedup_check: Callable[[str, str], bool] | None = None,
        on_sent: Callable[[str, str], None] | None = None,
    ) -> AlertDeliveryResult:
        """Evaluate routing rules and deliver a consolidated alert if warranted."""
        event_type = classify_alert_event(outcome)
        advisory_id = outcome.osv.id if outcome.osv is not None else None
        if event_type is None:
            return AlertDeliveryResult(
                advisory_id=advisory_id,
                event_type="skipped",
                delivered=False,
                reason="Outcome did not meet outbound alerting thresholds.",
            )

        payload, digest = build_webhook_payload(
            outcome,
            event_type=event_type,
            triage_id=triage_id,
        )
        if (
            event_type == "triage_review"
            and triage_id is not None
            and dedup_check is not None
            and not dedup_check(triage_id, digest)
        ):
            return AlertDeliveryResult(
                advisory_id=advisory_id,
                event_type="skipped",
                delivered=False,
                digest=digest,
                reason=f"Duplicate triage notification suppressed for {triage_id}.",
            )

        # Re-validate DNS before connecting to block DNS-rebinding TOCTOU on long-lived workers.
        validate_webhook_url(
            self._url,
            allow_insecure_http=self._allow_insecure_http,
            allow_private_targets=self._allow_private_targets,
            allowed_hosts=self._allowed_hosts,
            dns_resolver=self._dns_resolver,
        )

        headers: dict[str, str] = {}
        if self._signing_secret is not None:
            timestamp = int(time.time())
            raw_body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
            headers["X-ZeroBOM-Timestamp"] = str(timestamp)
            headers["X-ZeroBOM-Signature"] = sign_webhook_body(
                raw_body, self._signing_secret, timestamp
            )
            status = self._post_signed_bytes(raw_body, headers)
        else:
            status = _post_json_webhook(
                self._client,
                self._url,
                payload,
                headers=headers,
                backend_name="webhook",
            )

        if event_type == "triage_review" and triage_id is not None and on_sent is not None:
            on_sent(triage_id, digest)

        return AlertDeliveryResult(
            advisory_id=advisory_id,
            event_type=event_type,
            delivered=True,
            status_code=status,
            digest=digest,
        )

    def _post_signed_bytes(self, raw_body: bytes, extra_headers: Mapping[str, str]) -> int:
        """Post pre-serialized signed JSON bytes so the exact byte string matches HMAC."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **extra_headers,
        }
        try:
            with self._client.stream("POST", self._url, headers=headers, content=raw_body) as resp:
                status = resp.status_code
                buf = bytearray()
                for chunk in resp.iter_bytes():
                    if len(buf) + len(chunk) > _MAX_WEBHOOK_RESPONSE_BYTES:
                        break
                    buf.extend(chunk)
        except httpx.HTTPError as exc:
            raise AlertDeliveryError(
                f"Webhook delivery failed ({type(exc).__name__}) for "
                f"{redact_url_for_repr(self._url)}."
            ) from exc

        if status in REDIRECT_STATUS_CODES:
            raise AlertDeliveryError(
                f"Webhook redirect ({status}) refused for {redact_url_for_repr(self._url)}."
            )
        if not 200 <= status < 300:
            raise AlertDeliveryError(
                f"Webhook delivery returned HTTP {status} from {redact_url_for_repr(self._url)}."
            )
        return status

    def send_outcomes(
        self,
        outcomes: Sequence[PipelineOutcome],
        *,
        triage_ids: Mapping[str, str] | None = None,
        dedup_check: Callable[[str, str], bool] | None = None,
        on_sent: Callable[[str, str], None] | None = None,
    ) -> tuple[AlertDeliveryResult, ...]:
        """Deliver alerts across a sequence of :class:`PipelineOutcome` entries."""
        results: list[AlertDeliveryResult] = []
        for outcome in outcomes:
            adv_id = outcome.osv.id if outcome.osv is not None else None
            triage_id = triage_ids.get(adv_id) if (triage_ids and adv_id) else None
            results.append(
                self.send_outcome(
                    outcome,
                    triage_id=triage_id,
                    dedup_check=dedup_check,
                    on_sent=on_sent,
                )
            )
        return tuple(results)
