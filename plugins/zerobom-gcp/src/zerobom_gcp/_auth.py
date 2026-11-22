"""GCP authentication helpers with thread-safe auto-refreshing OAuth2 / ADC tokens."""

from __future__ import annotations

import importlib
import os
import threading
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from zerobom.backends import BackendConfigError, BackendQueryError
from zerobom.backends._http import validate_no_control_chars

DEFAULT_GCP_SCOPES: tuple[str, ...] = ("https://www.googleapis.com/auth/cloud-platform",)
_REFRESH_SKEW_SECONDS = 60


def _is_token_expiring_soon(creds: Any) -> bool:
    """Return True if ADC ``expiry`` is within ``_REFRESH_SKEW_SECONDS`` of UTC now."""
    expiry = getattr(creds, "expiry", None)
    if not isinstance(expiry, datetime):
        return False
    expiry_utc = expiry.replace(tzinfo=UTC) if expiry.tzinfo is None else expiry.astimezone(UTC)
    return datetime.now(UTC) + timedelta(seconds=_REFRESH_SKEW_SECONDS) >= expiry_utc


class GcpTokenProvider:
    """Thread-safe GCP OAuth2 bearer token provider supporting ADC auto-refresh."""

    def __init__(
        self,
        *,
        access_token: str | None = None,
        env_var: str = "ZEROBOM_GCP_ACCESS_TOKEN",
        use_adc: bool | None = None,
        scopes: Sequence[str] = DEFAULT_GCP_SCOPES,
        quota_project_id: str | None = None,
        credentials: Any | None = None,
        auth_request: Any | None = None,
    ) -> None:
        """Initialize the GCP credential provider.

        Resolution priority (unless explicit ``credentials`` object is supplied for testing):
        1. Explicit ``access_token`` string (static).
        2. Environment variables ``env_var``, ``ZEROBOM_GCP_TOKEN``, or
           ``GOOGLE_OAUTH_ACCESS_TOKEN`` (static).
        3. Application Default Credentials via ``google-auth`` when ``use_adc`` is ``True``
           or ``None`` (auto-fallback). Setting ``use_adc=False`` disables ADC fallback.

        Raises:
            BackendConfigError: If no credential source succeeds or validation fails.
        """
        if use_adc is not None and not isinstance(use_adc, bool):
            raise BackendConfigError("Configuration option 'use_adc' must be a bool.")

        self._lock = threading.Lock()
        self._static_token: str | None = None
        self._credentials: Any | None = None
        self._auth_request: Any | None = auth_request
        self._quota_project_id: str | None = quota_project_id

        if credentials is not None:
            self._credentials = credentials
            if self._quota_project_id is None:
                creds_qp = getattr(credentials, "quota_project_id", None)
                if isinstance(creds_qp, str) and creds_qp.strip():
                    self._quota_project_id = creds_qp.strip()
            self._acquire_initial_adc_token()
            return

        if access_token is not None:
            self._static_token = validate_no_control_chars(
                access_token, field_name="access_token", max_length=8192
            )
            return

        for candidate_env in (env_var, "ZEROBOM_GCP_TOKEN", "GOOGLE_OAUTH_ACCESS_TOKEN"):
            raw_env = os.environ.get(candidate_env)
            if raw_env and raw_env.strip():
                self._static_token = validate_no_control_chars(
                    raw_env, field_name=candidate_env, max_length=8192
                )
                return

        if use_adc is False:
            raise BackendConfigError(
                f"GCP backend requires 'access_token', {env_var}, ZEROBOM_GCP_TOKEN, "
                "GOOGLE_OAUTH_ACCESS_TOKEN, or use_adc=True."
            )

        try:
            google_auth = importlib.import_module("google.auth")
            if self._auth_request is None:
                google_requests = importlib.import_module("google.auth.transport.requests")
                self._auth_request = google_requests.Request()
            creds, detected_project = google_auth.default(scopes=list(scopes))
        except ImportError as exc:
            raise BackendConfigError(
                "GCP ADC requires 'google-auth[requests]' to be installed."
            ) from exc
        except Exception as exc:
            raise BackendConfigError(
                f"Failed to acquire GCP Application Default Credentials ({exc}). "
                f"Configure {env_var}, ZEROBOM_GCP_TOKEN, or run "
                "'gcloud auth application-default login'."
            ) from exc

        self._credentials = creds
        if self._quota_project_id is None:
            creds_qp = getattr(creds, "quota_project_id", None)
            if isinstance(creds_qp, str) and creds_qp.strip():
                self._quota_project_id = creds_qp.strip()
            elif isinstance(detected_project, str) and detected_project.strip():
                self._quota_project_id = detected_project.strip()
        self._acquire_initial_adc_token()

    def _acquire_initial_adc_token(self) -> None:
        """Eagerly verify/acquire initial ADC token during initialization."""
        try:
            self.get_token()
        except BackendQueryError as exc:
            raise BackendConfigError(str(exc)) from exc

    @property
    def can_refresh(self) -> bool:
        """Return True if this provider backs refreshable ADC credentials."""
        return self._credentials is not None

    @property
    def quota_project_id(self) -> str | None:
        """Return optional user/quota project identifier attached to GCP API calls."""
        return self._quota_project_id

    def get_token(self, *, force_refresh: bool = False) -> str:
        """Return a valid bearer token, refreshing ADC transparently if expired."""
        if self._static_token is not None:
            return self._static_token

        with self._lock:
            creds = self._credentials
            if creds is None:
                raise BackendConfigError("GCP credentials are not configured.")

            current_token = getattr(creds, "token", None)
            is_valid = bool(getattr(creds, "valid", current_token is not None))
            is_expired = bool(getattr(creds, "expired", False))
            needs_refresh = (
                force_refresh
                or current_token is None
                or not is_valid
                or is_expired
                or _is_token_expiring_soon(creds)
            )
            if needs_refresh:
                try:
                    creds.refresh(self._auth_request)
                except Exception as exc:
                    raise BackendQueryError(
                        f"Failed to refresh GCP OAuth2 credentials: {exc}"
                    ) from exc

            token_val = getattr(creds, "token", None)
            return validate_no_control_chars(token_val, field_name="gcp_adc_token", max_length=8192)


def resolve_gcp_bearer_token(
    access_token: str | None,
    *,
    env_var: str = "ZEROBOM_GCP_ACCESS_TOKEN",
    use_adc: bool | None = None,
    scopes: Sequence[str] = DEFAULT_GCP_SCOPES,
) -> str:
    """Resolve an initial bounded GCP OAuth2 bearer credential without control characters."""
    provider = GcpTokenProvider(
        access_token=access_token,
        env_var=env_var,
        use_adc=use_adc,
        scopes=scopes,
    )
    return provider.get_token()
