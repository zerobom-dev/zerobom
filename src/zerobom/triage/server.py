"""Zero-dependency signed Slack HTTP callback server and optional Socket Mode worker."""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import re
import threading
import time
from collections.abc import Callable, Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs

import httpx

from zerobom.backends import BackendError, SbomParseError
from zerobom.backends._http import validate_bounded_int, validate_timeout_seconds
from zerobom.ingest.fetcher import DnsResolver, default_dns_resolver
from zerobom.outputs.slack import SLACK_WEBHOOK_HOSTS
from zerobom.outputs.webhook import AlertDeliveryError, _post_json_webhook, validate_webhook_url
from zerobom.triage.actions import TriageActionHandler, parse_slack_interaction_payload
from zerobom.triage.store import TriageError

MAX_SLACK_CALLBACK_BYTES = 256 * 1024
DEFAULT_SIGNATURE_MAX_SKEW_SECONDS = 300
_SLACK_SIG_RE = re.compile(r"^v0=[0-9a-f]{64}$")


def verify_slack_signature(
    body: bytes,
    *,
    timestamp_header: str | None,
    signature_header: str | None,
    signing_secret: str,
    now: int | None = None,
    max_skew_seconds: int = DEFAULT_SIGNATURE_MAX_SKEW_SECONDS,
) -> bool:
    """Verify Slack ``X-Slack-Signature`` HMAC-SHA256 with replay timestamp checks.

    Args:
        body: Exact raw HTTP POST body bytes.
        timestamp_header: Value of ``X-Slack-Request-Timestamp``.
        signature_header: Value of ``X-Slack-Signature`` (``v0=<64-hex>``).
        signing_secret: Slack App Signing Secret.
        now: Optional current UNIX timestamp override for deterministic tests.
        max_skew_seconds: Maximum allowed timestamp drift in seconds (default ``300``).

    Returns:
        ``True`` only if signature format, timestamp replay window, and HMAC match cleanly.
    """
    if not signing_secret or not timestamp_header or not signature_header:
        return False

    ts_str = timestamp_header.strip()
    sig_str = signature_header.strip().lower()
    if not ts_str.isdigit() or not _SLACK_SIG_RE.fullmatch(sig_str):
        return False

    req_ts = int(ts_str)
    current_ts = int(time.time()) if now is None else now
    if abs(current_ts - req_ts) > max_skew_seconds:
        return False

    base_string = f"v0:{ts_str}:".encode("ascii") + body
    expected_digest = hmac.new(
        signing_secret.encode("utf-8"),
        base_string,
        hashlib.sha256,
    ).hexdigest()
    expected_sig = f"v0={expected_digest}"
    return hmac.compare_digest(expected_sig, sig_str)


def post_slack_response_url(
    response_url: str,
    payload: Mapping[str, Any],
    *,
    allowed_hosts: frozenset[str] = SLACK_WEBHOOK_HOSTS,
    dns_resolver: DnsResolver = default_dns_resolver,
    http_client: httpx.Client | None = None,
    timeout_seconds: float = 10.0,
) -> int:
    """Post a Slack interactive message update to a strictly host-pinned ``response_url``.

    Raises:
        AlertDeliveryError: If ``response_url`` targets a disallowed/private host or fails.
    """
    validated_url = validate_webhook_url(
        response_url,
        allow_insecure_http=False,
        allow_private_targets=False,
        allowed_hosts=allowed_hosts,
        dns_resolver=dns_resolver,
    )
    if http_client is not None:
        return _post_json_webhook(
            http_client,
            validated_url,
            payload,
            backend_name="slack_response",
        )

    with httpx.Client(timeout=timeout_seconds, follow_redirects=False, trust_env=False) as client:
        return _post_json_webhook(
            client,
            validated_url,
            payload,
            backend_name="slack_response",
        )


class _ReusableThreadingHTTPServer(ThreadingHTTPServer):
    """Stdlib multi-threaded HTTP server tuned for prompt restart and clean shutdown."""

    allow_reuse_address = True
    daemon_threads = True


class TriageWebhookServer:
    """Zero-dependency HTTP server receiving signed Slack interactive callbacks with <3s ack."""

    def __init__(
        self,
        handler: TriageActionHandler,
        *,
        signing_secret: str,
        host: str = "127.0.0.1",
        port: int = 8787,
        callback_path: str = "/slack/actions",
        max_body_bytes: int = MAX_SLACK_CALLBACK_BYTES,
        max_skew_seconds: int = DEFAULT_SIGNATURE_MAX_SKEW_SECONDS,
        request_timeout_seconds: float = 10.0,
        max_concurrent_requests: int = 32,
        response_allowed_hosts: frozenset[str] = SLACK_WEBHOOK_HOSTS,
        dns_resolver: DnsResolver = default_dns_resolver,
        response_http_client: httpx.Client | None = None,
        now_fn: Callable[[], int] | None = None,
    ) -> None:
        """Initialize the signed Slack HTTP triage callback worker.

        Args:
            handler: Shared :class:`TriageActionHandler` executing approve/reject actions.
            signing_secret: Slack App Signing Secret used to verify ``X-Slack-Signature``.
            host: Bind interface (defaults to loopback ``127.0.0.1``).
            port: TCP port (``0`` binds an ephemeral test port).
            callback_path: HTTP POST route handling interactive callbacks.
            max_body_bytes: Maximum incoming HTTP request payload ceiling.
            max_skew_seconds: Timestamp replay tolerance in seconds (default ``300``).
            request_timeout_seconds: Socket read timeout per connection (Slowloris defense).
            max_concurrent_requests: Maximum simultaneous in-flight POST handlers.
            response_allowed_hosts: Pinned allowlist for Slack ``response_url`` updates.
            dns_resolver: DNS resolver injected for URL/SSRF verification.
            response_http_client: Optional :class:`httpx.Client` for ``response_url`` POSTs.
            now_fn: Optional clock function returning epoch seconds for deterministic tests.
        """
        if not isinstance(signing_secret, str) or not signing_secret.strip():
            raise TriageError("Slack callback server requires a non-empty signing_secret.")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in signing_secret):
            raise TriageError("signing_secret must not contain control characters.")

        try:
            self._request_timeout_seconds = validate_timeout_seconds(request_timeout_seconds)
            conc_limit = validate_bounded_int(
                max_concurrent_requests,
                field_name="max_concurrent_requests",
                min_value=1,
                max_value=256,
            )
        except (BackendError, ValueError) as exc:
            raise TriageError(str(exc)) from exc

        cleaned_path = "/" + callback_path.strip().lstrip("/")
        if not cleaned_path or " " in cleaned_path:
            raise TriageError(f"Invalid callback_path: {callback_path!r}.")

        self._handler = handler
        self._signing_secret = signing_secret
        self._callback_path = cleaned_path
        self._max_body_bytes = max_body_bytes
        self._max_skew_seconds = max_skew_seconds
        self._inflight_sem = threading.BoundedSemaphore(conc_limit)
        self._response_allowed_hosts = response_allowed_hosts
        self._dns_resolver = dns_resolver
        self._response_http_client = response_http_client
        self._now_fn = now_fn

        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="zerobom-triage")
        self._pending_lock = threading.Lock()
        self._pending: set[Future[None]] = set()
        self._errors_lock = threading.Lock()
        self._background_errors: list[str] = []

        request_handler_cls = self._build_request_handler()
        self._httpd = _ReusableThreadingHTTPServer((host, port), request_handler_cls)

    @property
    def server_address(self) -> tuple[str, int]:
        """Return bound ``(host, port)`` tuple."""
        addr = self._httpd.server_address
        return str(addr[0]), int(addr[1])

    @property
    def server_port(self) -> int:
        """Return the bound TCP port."""
        return self.server_address[1]

    @property
    def background_errors(self) -> tuple[str, ...]:
        """Return any errors captured while executing async triage background tasks."""
        with self._errors_lock:
            return tuple(self._background_errors)

    def serve_forever(self) -> None:
        """Start serving signed HTTP callbacks until :meth:`shutdown` is called."""
        self._httpd.serve_forever()

    def shutdown(self) -> None:
        """Stop the HTTP server loop cleanly."""
        self._httpd.shutdown()

    def wait_for_pending(self, timeout: float = 5.0) -> None:
        """Block until all currently queued async triage tasks complete."""
        with self._pending_lock:
            futures = list(self._pending)
        deadline = time.monotonic() + timeout
        for fut in futures:
            remaining = max(0.01, deadline - time.monotonic())
            fut.result(timeout=remaining)

    def close(self) -> None:
        """Shutdown background worker pool and close the listening socket."""
        self._httpd.server_close()
        self._executor.shutdown(wait=True)

    def __enter__(self) -> TriageWebhookServer:
        """Enter context manager returning self."""
        return self

    def __exit__(self, *_: object) -> None:
        """Ensure sockets and background executor close on context exit."""
        self.close()

    def _submit_interaction(self, payload: Mapping[str, Any]) -> str:
        """Validate interaction payload, schedule async execution, and return ack text."""
        req = parse_slack_interaction_payload(payload)

        def _worker() -> None:
            try:
                _, slack_update = self._handler.execute_slack_interaction(req)
            except (
                TriageError,
                BackendError,
                SbomParseError,
                AlertDeliveryError,
                ValueError,
                RuntimeError,
            ) as exc:
                with self._errors_lock:
                    if len(self._background_errors) < 100:
                        self._background_errors.append(str(exc))
                if req.response_url is not None:
                    err_payload = {
                        "response_type": "ephemeral",
                        "replace_original": False,
                        "text": f"zerobom triage action failed for {req.triage_id}.",
                    }
                    with suppress(AlertDeliveryError, ValueError):
                        post_slack_response_url(
                            req.response_url,
                            err_payload,
                            allowed_hosts=self._response_allowed_hosts,
                            dns_resolver=self._dns_resolver,
                            http_client=self._response_http_client,
                        )
                return

            if req.response_url is not None:
                try:
                    post_slack_response_url(
                        req.response_url,
                        slack_update,
                        allowed_hosts=self._response_allowed_hosts,
                        dns_resolver=self._dns_resolver,
                        http_client=self._response_http_client,
                    )
                except (AlertDeliveryError, ValueError, RuntimeError) as exc:
                    with self._errors_lock:
                        if len(self._background_errors) < 100:
                            self._background_errors.append(str(exc))

        future = self._executor.submit(_worker)
        with self._pending_lock:
            self._pending.add(future)

        def _cleanup(done_future: Future[None]) -> None:
            with self._pending_lock:
                self._pending.discard(done_future)

        future.add_done_callback(_cleanup)
        return f"Processing {req.action_id} for {req.triage_id}..."

    def _build_request_handler(self) -> type[BaseHTTPRequestHandler]:
        """Construct a stdlib HTTP handler class bound to this server instance."""
        owner = self

        class _TriageRequestHandler(BaseHTTPRequestHandler):
            def setup(self) -> None:
                # Enforce per-connection read timeout so slow clients cannot stall worker threads.
                self.request.settimeout(owner._request_timeout_seconds)
                super().setup()

            def log_message(self, format: str, *args: object) -> None:
                # Suppress raw stderr request logging to keep stdout/logs clean of tokens/noise.
                del format, args

            def _send_json(
                self,
                status: int,
                body_obj: Mapping[str, Any],
                *,
                close: bool = False,
            ) -> None:
                encoded = json.dumps(body_obj).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded)))
                if close:
                    self.send_header("Connection", "close")
                    self.close_connection = True
                self.end_headers()
                self.wfile.write(encoded)
                self.wfile.flush()

            def _drain_request_body(self, max_drain_bytes: int) -> None:
                # Drain bounded unread POST payloads before Connection: close so TCP/Windows
                # sockets receive the 404/503/413 HTTP response cleanly instead of a reset.
                raw_cl = self.headers.get("Content-Length")
                if raw_cl is None or not raw_cl.strip().isdigit():
                    return
                remaining = int(raw_cl.strip())
                if remaining <= 0 or remaining > max_drain_bytes:
                    return
                while remaining > 0:
                    try:
                        chunk = self.rfile.read(min(remaining, 65536))
                    except (TimeoutError, OSError):
                        break
                    if not chunk:
                        break
                    remaining -= len(chunk)

            def do_GET(self) -> None:
                path_only = self.path.split("?", 1)[0]
                if path_only == "/healthz":
                    self._send_json(200, {"status": "ok"})
                    return
                self._send_json(404, {"error": "not_found"})

            def do_POST(self) -> None:
                path_only = self.path.split("?", 1)[0]
                if path_only != owner._callback_path:
                    self._drain_request_body(owner._max_body_bytes)
                    self._send_json(404, {"error": "not_found"}, close=True)
                    return

                if not owner._inflight_sem.acquire(blocking=False):
                    self._drain_request_body(owner._max_body_bytes)
                    self._send_json(503, {"error": "server_busy"}, close=True)
                    return

                try:
                    raw_cl = self.headers.get("Content-Length")
                    if raw_cl is None or not raw_cl.strip().isdigit():
                        self._send_json(400, {"error": "invalid_content_length"}, close=True)
                        return
                    content_length = int(raw_cl.strip())
                    if content_length > owner._max_body_bytes:
                        # Drain modest overruns so TCP stack delivers 413 cleanly without RST.
                        self._drain_request_body(owner._max_body_bytes * 4)
                        self._send_json(413, {"error": "payload_too_large"}, close=True)
                        return

                    try:
                        raw_body = self.rfile.read(content_length)
                    except (TimeoutError, OSError):
                        self.close_connection = True
                        return

                    if len(raw_body) != content_length:
                        self._send_json(400, {"error": "incomplete_body"}, close=True)
                        return

                    now_ts = owner._now_fn() if owner._now_fn is not None else None
                    if not verify_slack_signature(
                        raw_body,
                        timestamp_header=self.headers.get("X-Slack-Request-Timestamp"),
                        signature_header=self.headers.get("X-Slack-Signature"),
                        signing_secret=owner._signing_secret,
                        now=now_ts,
                        max_skew_seconds=owner._max_skew_seconds,
                    ):
                        self._send_json(401, {"error": "invalid_signature"})
                        return

                    try:
                        form_text = raw_body.decode("utf-8")
                        parsed_form = parse_qs(form_text, strict_parsing=False)
                        raw_payload_list = parsed_form.get("payload")
                        if not raw_payload_list:
                            raise ValueError("Missing 'payload' form parameter.")
                        payload_dict = json.loads(raw_payload_list[0])
                        if not isinstance(payload_dict, Mapping):
                            raise ValueError("Interaction payload must be a JSON object.")
                        ack_text = owner._submit_interaction(payload_dict)
                    except (
                        UnicodeDecodeError,
                        json.JSONDecodeError,
                        RecursionError,
                        ValueError,
                        TriageError,
                    ) as exc:
                        self._send_json(400, {"error": f"invalid_payload: {exc}"})
                        return

                    # Acknowledge immediately within Slack's 3-second deadline.
                    self._send_json(
                        200,
                        {
                            "response_type": "ephemeral",
                            "replace_original": False,
                            "text": ack_text,
                        },
                    )
                finally:
                    owner._inflight_sem.release()

        return _TriageRequestHandler


class _SocketModeHandle(threading.Event):
    """``threading.Event`` subclass attaching clean ``sm_client`` shutdown via ``close()``."""

    def __init__(self, sm_client: Any) -> None:
        super().__init__()
        self._sm_client = sm_client

    def close(self) -> None:
        """Signal shutdown and close the underlying Socket Mode client session."""
        self.set()
        close_fn = getattr(self._sm_client, "close", None)
        if callable(close_fn):
            close_fn()
        else:
            disc_fn = getattr(self._sm_client, "disconnect", None)
            if callable(disc_fn):
                disc_fn()


def run_socket_mode_worker(
    handler: TriageActionHandler,
    *,
    app_token: str,
    bot_token: str,
    allowed_response_hosts: frozenset[str] = SLACK_WEBHOOK_HOSTS,
    dns_resolver: DnsResolver = default_dns_resolver,
) -> _SocketModeHandle:
    """Start an optional Slack Socket Mode listener sharing :class:`TriageActionHandler`.

    Lazily imports ``slack_sdk`` so core ``zerobom`` retains zero mandatory Slack SDK
    dependencies.
    """
    if not app_token.strip() or not bot_token.strip():
        raise TriageError("Slack Socket Mode requires both non-empty app_token and bot_token.")

    try:
        slack_web = importlib.import_module("slack_sdk.web")
        slack_sm = importlib.import_module("slack_sdk.socket_mode")
        slack_sm_resp = importlib.import_module("slack_sdk.socket_mode.response")
    except ImportError as exc:
        raise RuntimeError(
            "Socket Mode triage worker requires optional package 'slack-sdk' "
            "(pip install slack-sdk), or use default HTTP mode ('--transport http')."
        ) from exc

    web_client = slack_web.WebClient(token=bot_token)
    sm_client = slack_sm.SocketModeClient(app_token=app_token, web_client=web_client)
    stop_handle = _SocketModeHandle(sm_client)

    def _process(client: Any, req_envelope: Any) -> None:
        if getattr(req_envelope, "type", None) != "interactive":
            return
        client.send_socket_mode_response(
            slack_sm_resp.SocketModeResponse(envelope_id=req_envelope.envelope_id)
        )
        raw_payload = getattr(req_envelope, "payload", None)
        if not isinstance(raw_payload, Mapping):
            return
        try:
            interaction = parse_slack_interaction_payload(raw_payload)
        except (TriageError, ValueError):
            return

        try:
            _, slack_update = handler.execute_slack_interaction(interaction)
        except (
            TriageError,
            BackendError,
            SbomParseError,
            AlertDeliveryError,
            ValueError,
            RuntimeError,
        ):
            if interaction.response_url is not None:
                with suppress(AlertDeliveryError, ValueError):
                    post_slack_response_url(
                        interaction.response_url,
                        {
                            "response_type": "ephemeral",
                            "replace_original": False,
                            "text": f"zerobom triage action failed for {interaction.triage_id}.",
                        },
                        allowed_hosts=allowed_response_hosts,
                        dns_resolver=dns_resolver,
                    )
            return

        if interaction.response_url is not None:
            with suppress(AlertDeliveryError, ValueError):
                post_slack_response_url(
                    interaction.response_url,
                    slack_update,
                    allowed_hosts=allowed_response_hosts,
                    dns_resolver=dns_resolver,
                )

    sm_client.socket_mode_request_listeners.append(_process)
    sm_client.connect()
    return stop_handle
