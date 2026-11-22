"""Shared AWS session, STS AssumeRole, validation, and boto3 client builders."""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
import botocore.credentials
import botocore.session
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError

from zerobom._version import __version__
from zerobom.backends import BackendConfigError
from zerobom.backends._http import (
    validate_api_base_url,
    validate_bounded_int,
    validate_no_control_chars,
)

AWS_REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+$")
AWS_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
AWS_ROLE_ARN_RE = re.compile(r"^arn:aws(?:-[a-z-]+)?:iam::[0-9]{12}:role/[\w+=,.@/-]{1,512}$")
AWS_ORG_ID_RE = re.compile(r"^o-[a-z0-9]{10,32}$")
AWS_OU_ID_RE = re.compile(r"^ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}$")
AWS_KMS_KEY_ARN_RE = re.compile(
    r"^arn:aws(?:-[a-z-]+)?:kms:[a-z]{2}(?:-[a-z]+)+-[0-9]+:[0-9]{12}:key/[A-Za-z0-9-]+$"
)


def validate_aws_region(region_name: str | None) -> str | None:
    """Validate an optional AWS region identifier against standard/Gov/China formats."""
    if region_name is None:
        return None
    cleaned = validate_no_control_chars(region_name, field_name="region_name", max_length=64)
    if not AWS_REGION_RE.fullmatch(cleaned):
        raise BackendConfigError(f"Invalid AWS region_name: {region_name!r}.")
    return cleaned


def resolve_env_aws_region(explicit_region: str | None) -> str | None:
    """Resolve explicit region config or ``AWS_REGION`` / ``AWS_DEFAULT_REGION``."""
    if explicit_region is not None:
        return validate_aws_region(explicit_region)
    raw_env = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    if raw_env and raw_env.strip():
        return validate_aws_region(raw_env)
    return None


def validate_aws_account_id(account_id: str, *, field_name: str = "account_id") -> str:
    """Validate a 12-digit AWS account identifier."""
    cleaned = validate_no_control_chars(account_id, field_name=field_name, max_length=12)
    if not AWS_ACCOUNT_RE.fullmatch(cleaned):
        raise BackendConfigError(f"Invalid 12-digit AWS account_id: {account_id!r}.")
    return cleaned


def validate_aws_account_ids(account_ids: Sequence[str]) -> tuple[str, ...]:
    """Validate a sequence of 12-digit AWS account IDs."""
    return tuple(validate_aws_account_id(acc, field_name="account_ids") for acc in account_ids)


def validate_aws_role_arn(role_arn: str | None) -> str | None:
    """Validate an optional IAM role ARN for STS AssumeRole."""
    if role_arn is None:
        return None
    cleaned = validate_no_control_chars(role_arn, field_name="role_arn", max_length=512)
    if ".." in cleaned or not AWS_ROLE_ARN_RE.fullmatch(cleaned):
        raise BackendConfigError(f"Invalid AWS IAM role_arn: {role_arn!r}.")
    return cleaned


def validate_aws_org_id(organization_id: str | None) -> str | None:
    """Validate an optional AWS Organizations ID (``o-...``)."""
    if organization_id is None:
        return None
    cleaned = validate_no_control_chars(
        organization_id, field_name="organization_id", max_length=40
    )
    if not AWS_ORG_ID_RE.fullmatch(cleaned):
        raise BackendConfigError(f"Invalid AWS organization_id: {organization_id!r}.")
    return cleaned


def validate_aws_ou_ids(ou_ids: Sequence[str]) -> tuple[str, ...]:
    """Validate optional AWS Organizations Organizational Unit IDs (``ou-...``)."""
    validated: list[str] = []
    for raw_ou in ou_ids:
        cleaned = validate_no_control_chars(
            raw_ou, field_name="organizational_unit_ids", max_length=80
        )
        if not AWS_OU_ID_RE.fullmatch(cleaned):
            raise BackendConfigError(f"Invalid AWS organizational_unit_id: {raw_ou!r}.")
        validated.append(cleaned)
    return tuple(validated)


def validate_aws_kms_key_arn(kms_key_arn: str | None) -> str | None:
    """Validate an optional AWS KMS key ARN for Inspector2 S3 encryption."""
    if kms_key_arn is None:
        return None
    cleaned = validate_no_control_chars(kms_key_arn, field_name="kms_key_arn", max_length=512)
    if not AWS_KMS_KEY_ARN_RE.fullmatch(cleaned):
        raise BackendConfigError(f"Invalid AWS kms_key_arn: {kms_key_arn!r}.")
    return cleaned


def build_refreshable_assume_role_credentials(
    *,
    role_arn: str,
    external_id: str | None = None,
    role_session_name: str = "zerobom-cloud-session",
    sts_client: Any,
) -> botocore.credentials.RefreshableCredentials:
    """Build auto-refreshing botocore credentials backed by STS ``AssumeRole``."""

    def _refresh() -> dict[str, Any]:
        params: dict[str, Any] = {
            "RoleArn": role_arn,
            "RoleSessionName": role_session_name,
        }
        if external_id is not None:
            params["ExternalId"] = external_id
        try:
            resp = sts_client.assume_role(**params)
        except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
            raise BackendConfigError(f"STS AssumeRole failed for {role_arn!r}: {exc}") from exc

        creds = resp.get("Credentials")
        if not isinstance(creds, dict):
            raise BackendConfigError(
                f"STS AssumeRole returned invalid Credentials for {role_arn!r}."
            )

        access_key = creds.get("AccessKeyId")
        secret_key = creds.get("SecretAccessKey")
        session_token = creds.get("SessionToken")
        expiration = creds.get("Expiration")
        if (
            not isinstance(access_key, str)
            or not isinstance(secret_key, str)
            or not isinstance(session_token, str)
        ):
            raise BackendConfigError(f"STS AssumeRole omitted credential fields for {role_arn!r}.")

        if isinstance(expiration, datetime):
            exp_dt = expiration if expiration.tzinfo is not None else expiration.replace(tzinfo=UTC)
        elif isinstance(expiration, str):
            exp_dt = datetime.fromisoformat(expiration)
        else:
            exp_dt = datetime.now(UTC) + timedelta(minutes=55)

        return {
            "access_key": access_key,
            "secret_key": secret_key,
            "token": session_token,
            "expiry_time": exp_dt.isoformat(),
        }

    initial_meta = _refresh()
    return botocore.credentials.RefreshableCredentials.create_from_metadata(
        metadata=initial_meta,
        refresh_using=_refresh,
        method="sts-assume-role",
    )


def build_aws_client(
    service_name: str,
    *,
    region_name: str | None = None,
    profile_name: str | None = None,
    role_arn: str | None = None,
    external_id: str | None = None,
    role_session_name: str = "zerobom-cloud-session",
    endpoint_url: str | None = None,
    allow_insecure_http: bool = False,
    timeout_seconds: float = 15.0,
    max_retries: int = 3,
    max_pool_connections: int = 10,
) -> Any:
    """Build a hardened boto3 service client with optional STS AssumeRole & retries."""
    if not isinstance(allow_insecure_http, bool):
        raise BackendConfigError("Configuration option 'allow_insecure_http' must be a bool.")

    validated_retries = validate_bounded_int(
        max_retries, field_name="max_retries", min_value=0, max_value=10
    )
    validated_pool = validate_bounded_int(
        max_pool_connections, field_name="max_pool_connections", min_value=1, max_value=64
    )
    validated_endpoint = (
        validate_api_base_url(
            endpoint_url,
            allow_insecure_http=allow_insecure_http,
            field_name="endpoint_url",
        )
        if endpoint_url is not None
        else None
    )
    validated_role = validate_aws_role_arn(role_arn)
    validated_ext_id = (
        validate_no_control_chars(external_id, field_name="external_id", max_length=1224)
        if external_id is not None
        else None
    )
    validated_session_name = validate_no_control_chars(
        role_session_name, field_name="role_session_name", max_length=64
    )

    boto_cfg = BotoConfig(
        connect_timeout=timeout_seconds,
        read_timeout=timeout_seconds,
        retries={"max_attempts": validated_retries + 1, "mode": "adaptive"},
        max_pool_connections=max(10, validated_pool),
        user_agent_extra=f"zerobom-aws/{__version__}",
    )

    if validated_role is not None:
        base_session = boto3.Session(region_name=region_name, profile_name=profile_name)
        sts_client = base_session.client(
            "sts",
            config=BotoConfig(
                connect_timeout=timeout_seconds,
                read_timeout=timeout_seconds,
                retries={"max_attempts": validated_retries + 1, "mode": "standard"},
                user_agent_extra=f"zerobom-aws/{__version__}",
            ),
        )
        refreshable = build_refreshable_assume_role_credentials(
            role_arn=validated_role,
            external_id=validated_ext_id,
            role_session_name=validated_session_name,
            sts_client=sts_client,
        )
        botocore_sess = botocore.session.get_session()
        botocore_sess._credentials = refreshable
        session = boto3.Session(botocore_session=botocore_sess, region_name=region_name)
    else:
        session = boto3.Session(region_name=region_name, profile_name=profile_name)

    client_kwargs: dict[str, Any] = {"config": boto_cfg}
    if validated_endpoint is not None:
        client_kwargs["endpoint_url"] = validated_endpoint
    return session.client(service_name, **client_kwargs)
