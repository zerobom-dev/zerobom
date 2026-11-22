"""Azure sovereign cloud presets and thread-safe auto-refreshing OAuth2 credentials."""

from __future__ import annotations

import importlib
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from zerobom.backends import BackendConfigError, BackendQueryError
from zerobom.backends._http import validate_no_control_chars

AZURE_MGMT_SCOPE = "https://management.azure.com/.default"
AZURE_STORAGE_SCOPE = "https://storage.azure.com/.default"
_REFRESH_SKEW_SECONDS = 60.0


@dataclass(frozen=True)
class AzureCloudPreset:
    """Regional and sovereign Azure cloud endpoints and Entra authorities."""

    name: str
    resource_manager_url: str
    blob_endpoint_suffix: str
    resource_manager_scope: str
    storage_scope: str
    authority: str


AZURE_CLOUD_PRESETS: dict[str, AzureCloudPreset] = {
    "commercial": AzureCloudPreset(
        name="commercial",
        resource_manager_url="https://management.azure.com",
        blob_endpoint_suffix="blob.core.windows.net",
        resource_manager_scope="https://management.azure.com/.default",
        storage_scope="https://storage.azure.com/.default",
        authority="https://login.microsoftonline.com",
    ),
    "usgov": AzureCloudPreset(
        name="usgov",
        resource_manager_url="https://management.usgovcloudapi.net",
        blob_endpoint_suffix="blob.core.usgovcloudapi.net",
        resource_manager_scope="https://management.usgovcloudapi.net/.default",
        storage_scope="https://storage.azure.com/.default",
        authority="https://login.microsoftonline.us",
    ),
    "china": AzureCloudPreset(
        name="china",
        resource_manager_url="https://management.chinacloudapi.cn",
        blob_endpoint_suffix="blob.core.chinacloudapi.cn",
        resource_manager_scope="https://management.chinacloudapi.cn/.default",
        storage_scope="https://storage.azure.com/.default",
        authority="https://login.chinacloudapi.cn",
    ),
}


def resolve_azure_cloud_preset(cloud: str) -> AzureCloudPreset:
    """Validate and resolve a named Azure cloud environment preset."""
    cleaned = validate_no_control_chars(cloud, field_name="cloud", max_length=32).lower()
    preset = AZURE_CLOUD_PRESETS.get(cleaned)
    if preset is None:
        valid = ", ".join(sorted(AZURE_CLOUD_PRESETS))
        raise BackendConfigError(f"Invalid Azure cloud preset {cloud!r}; expected one of: {valid}.")
    return preset


class AzureTokenProvider:
    """Thread-safe Azure OAuth2 bearer token provider supporting ``DefaultAzureCredential``."""

    def __init__(
        self,
        *,
        access_token: str | None = None,
        scope: str = AZURE_MGMT_SCOPE,
        env_var: str = "ZEROBOM_AZURE_ACCESS_TOKEN",
        use_default_credential: bool | None = None,
        authority: str | None = None,
        credential: Any | None = None,
        time_fn: Callable[[], float] = time.time,
    ) -> None:
        """Initialize the Azure OAuth2 token provider.

        Resolution priority (unless explicit ``credential`` test double is provided):
        1. Explicit ``access_token`` string (static).
        2. Environment variables ``env_var`` or ``ZEROBOM_AZURE_TOKEN`` (static).
        3. ``azure.identity.DefaultAzureCredential`` when ``use_default_credential`` is
           ``True`` or ``None`` (auto-fallback). Setting ``use_default_credential=False``
           disables fallback.

        Raises:
            BackendConfigError: If no credential source succeeds or validation fails.
        """
        if use_default_credential is not None and not isinstance(use_default_credential, bool):
            raise BackendConfigError(
                "Configuration option 'use_default_credential' must be a bool."
            )

        self._lock = threading.Lock()
        self._scope = scope
        self._time_fn = time_fn
        self._static_token: str | None = None
        self._credential: Any | None = None
        self._cached_token: str | None = None
        self._expires_on: float | None = None

        if credential is not None:
            self._credential = credential
            self._acquire_initial_token()
            return

        if access_token is not None:
            self._static_token = validate_no_control_chars(
                access_token, field_name="access_token", max_length=8192
            )
            return

        for candidate_env in (env_var, "ZEROBOM_AZURE_TOKEN"):
            raw_env = os.environ.get(candidate_env)
            if raw_env and raw_env.strip():
                self._static_token = validate_no_control_chars(
                    raw_env, field_name=candidate_env, max_length=8192
                )
                return

        if use_default_credential is False:
            raise BackendConfigError(
                f"Azure backend requires 'access_token', {env_var}, ZEROBOM_AZURE_TOKEN, "
                "or use_default_credential=True."
            )

        try:
            azure_identity = importlib.import_module("azure.identity")
            cred = (
                azure_identity.DefaultAzureCredential(authority=authority)
                if authority is not None
                else azure_identity.DefaultAzureCredential()
            )
        except ImportError as exc:
            raise BackendConfigError(
                "Azure credential fallback requires 'azure-identity' to be installed."
            ) from exc
        except Exception as exc:
            raise BackendConfigError(
                f"Failed to initialize Azure DefaultAzureCredential: {exc}"
            ) from exc

        self._credential = cred
        self._acquire_initial_token()

    def _acquire_initial_token(self) -> None:
        """Acquire initial token eagerly so missing/invalid credentials fail at startup."""
        try:
            self.get_token()
        except BackendQueryError as exc:
            raise BackendConfigError(str(exc)) from exc

    @property
    def can_refresh(self) -> bool:
        """Return True if backed by a refreshable ``DefaultAzureCredential``."""
        return self._credential is not None

    def get_token(self, *, force_refresh: bool = False) -> str:
        """Return a valid Azure OAuth2 bearer token, refreshing before expiry."""
        if self._static_token is not None:
            return self._static_token

        with self._lock:
            cred = self._credential
            if cred is None:
                raise BackendConfigError("Azure credentials are not configured.")

            now = self._time_fn()
            expired = (
                self._expires_on is not None and (now + _REFRESH_SKEW_SECONDS) >= self._expires_on
            )
            if force_refresh or self._cached_token is None or expired:
                try:
                    token_obj = cred.get_token(self._scope)
                except Exception as exc:
                    raise BackendQueryError(
                        f"Failed to acquire/refresh Azure token via DefaultAzureCredential: {exc}"
                    ) from exc

                token_str = validate_no_control_chars(
                    getattr(token_obj, "token", None),
                    field_name="azure_default_credential_token",
                    max_length=8192,
                )
                expires_on = getattr(token_obj, "expires_on", None)
                self._cached_token = token_str
                self._expires_on = (
                    float(expires_on)
                    if isinstance(expires_on, (int, float)) and not isinstance(expires_on, bool)
                    else None
                )

            return self._cached_token


def resolve_azure_bearer_token(
    access_token: str | None,
    *,
    scope: str = AZURE_MGMT_SCOPE,
    env_var: str = "ZEROBOM_AZURE_ACCESS_TOKEN",
    use_default_credential: bool | None = None,
) -> str:
    """Resolve an initial bounded Azure OAuth2 bearer credential without control characters."""
    provider = AzureTokenProvider(
        access_token=access_token,
        scope=scope,
        env_var=env_var,
        use_default_credential=use_default_credential,
    )
    return provider.get_token()
