"""GCP authentication helpers supporting direct OAuth2 tokens and optional ADC."""

from __future__ import annotations

import importlib
import os
from collections.abc import Sequence

from zerobom.backends import BackendConfigError
from zerobom.backends._http import validate_no_control_chars

DEFAULT_GCP_SCOPES: tuple[str, ...] = ("https://www.googleapis.com/auth/cloud-platform",)


def resolve_gcp_bearer_token(
    access_token: str | None,
    *,
    env_var: str = "ZEROBOM_GCP_ACCESS_TOKEN",
    use_adc: bool = False,
    scopes: Sequence[str] = DEFAULT_GCP_SCOPES,
) -> str:
    """Resolve a bounded GCP OAuth2 bearer credential without control characters.

    Resolution priority:
    1. Explicit ``access_token`` argument.
    2. ``env_var`` (defaults to ``ZEROBOM_GCP_ACCESS_TOKEN``) or ``GOOGLE_OAUTH_ACCESS_TOKEN``.
    3. Optional Application Default Credentials via ``google-auth`` when ``use_adc=True``.

    Raises:
        BackendConfigError: If no credential source succeeds or ``google-auth`` is missing.
    """
    if access_token is not None:
        return validate_no_control_chars(access_token, field_name="access_token", max_length=8192)

    for candidate_env in (env_var, "GOOGLE_OAUTH_ACCESS_TOKEN"):
        raw_env = os.environ.get(candidate_env)
        if raw_env and raw_env.strip():
            return validate_no_control_chars(raw_env, field_name=candidate_env, max_length=8192)

    if use_adc:
        try:
            google_auth = importlib.import_module("google.auth")
            google_requests = importlib.import_module("google.auth.transport.requests")
            creds, _ = google_auth.default(scopes=list(scopes))
            creds.refresh(google_requests.Request())
        except ImportError as exc:
            raise BackendConfigError(
                "use_adc=True requires optional package 'google-auth' (pip install google-auth)."
            ) from exc
        except Exception as exc:
            raise BackendConfigError(
                f"Failed to acquire GCP Application Default Credentials: {exc}"
            ) from exc

        adc_val = getattr(creds, "token", None)
        return validate_no_control_chars(adc_val, field_name="gcp_adc_token", max_length=8192)

    raise BackendConfigError(
        f"GCP backend requires 'access_token', {env_var}, "
        "GOOGLE_OAUTH_ACCESS_TOKEN, or use_adc=True."
    )
