"""Azure authentication helpers supporting OAuth2 bearer tokens and optional ``azure-identity``."""

from __future__ import annotations

import importlib
import os

from zerobom.backends import BackendConfigError
from zerobom.backends._http import validate_no_control_chars

AZURE_MGMT_SCOPE = "https://management.azure.com/.default"
AZURE_STORAGE_SCOPE = "https://storage.azure.com/.default"


def resolve_azure_bearer_token(
    access_token: str | None,
    *,
    scope: str = AZURE_MGMT_SCOPE,
    env_var: str = "ZEROBOM_AZURE_ACCESS_TOKEN",
    use_default_credential: bool = False,
) -> str:
    """Resolve a bounded Azure OAuth2 bearer credential without control characters.

    Resolution priority:
    1. Explicit ``access_token`` argument.
    2. ``env_var`` environment variable.
    3. Optional ``azure.identity.DefaultAzureCredential`` when ``use_default_credential=True``.

    Raises:
        BackendConfigError: If no credential source succeeds or ``azure-identity`` is missing.
    """
    if access_token is not None:
        return validate_no_control_chars(access_token, field_name="access_token", max_length=8192)

    raw_env = os.environ.get(env_var)
    if raw_env and raw_env.strip():
        return validate_no_control_chars(raw_env, field_name=env_var, max_length=8192)

    if use_default_credential:
        try:
            azure_identity = importlib.import_module("azure.identity")
            cred = azure_identity.DefaultAzureCredential()
            token_obj = cred.get_token(scope)
        except ImportError as exc:
            raise BackendConfigError(
                "use_default_credential=True requires optional package 'azure-identity' "
                "(pip install azure-identity)."
            ) from exc
        except Exception as exc:
            raise BackendConfigError(
                f"Failed to acquire Azure token via DefaultAzureCredential: {exc}"
            ) from exc

        token_str = getattr(token_obj, "token", None)
        return validate_no_control_chars(
            token_str, field_name="azure_default_credential_token", max_length=8192
        )

    raise BackendConfigError(
        f"Azure backend requires 'access_token', {env_var}, or use_default_credential=True."
    )
