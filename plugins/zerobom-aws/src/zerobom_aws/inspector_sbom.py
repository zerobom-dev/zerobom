"""Amazon Inspector v2 SBOM export (CycloneDX 1.4 / SPDX 2.3) backend plugin."""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from zerobom.backends import (
    BackendConfigError,
    BackendQueryError,
    InMemoryComponentIndex,
)
from zerobom.backends._http import (
    DEFAULT_API_TIMEOUT_SECONDS,
    MAX_API_URL_LENGTH,
    parse_bool_opt,
    parse_float_opt,
    parse_int_opt,
    parse_optional_str_opt,
    parse_str_list_opt,
    reject_unknown_config_keys,
    validate_bounded_int,
    validate_no_control_chars,
    validate_timeout_seconds,
)
from zerobom.backends.sbom_parser import MAX_SBOM_FILE_BYTES, clean_optional_str
from zerobom.models import InventoryComponent, PackageQuery
from zerobom_aws._common import (
    DEFAULT_SBOM_SUFFIXES,
    load_s3_sbom_prefix,
    validate_s3_bucket,
    validate_s3_prefix,
)
from zerobom_aws._session import (
    build_aws_client,
    resolve_env_aws_region,
    validate_aws_account_id,
    validate_aws_account_ids,
    validate_aws_kms_key_arn,
    validate_aws_region,
)

_REPORT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{4,128}$")
_VALID_REPORT_FORMATS: frozenset[str] = frozenset({"CYCLONEDX_1_4", "SPDX_2_3"})
_VALID_INSPECTOR_RESOURCE_TYPES: frozenset[str] = frozenset(
    {"AWS_EC2_INSTANCE", "AWS_ECR_CONTAINER_IMAGE", "AWS_LAMBDA_FUNCTION"}
)
_MAX_POLL_INTERVAL_SECONDS = 30.0

_ALLOWED_CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "report_id",
        "trigger_export",
        "s3_bucket",
        "s3_prefix",
        "kms_key_arn",
        "expected_bucket_owner",
        "report_format",
        "account_ids",
        "resource_types",
        "ecr_repositories",
        "lambda_functions",
        "wait_for_completion",
        "poll_interval_seconds",
        "poll_timeout_seconds",
        "region_name",
        "profile_name",
        "role_arn",
        "external_id",
        "role_session_name",
        "endpoint_url",
        "s3_endpoint_url",
        "allow_insecure_http",
        "suffixes",
        "max_objects",
        "max_pages",
        "max_sbom_bytes",
        "max_concurrency",
        "max_retries",
        "timeout_seconds",
        "skip_archived",
        "strict",
    }
)


class AwsInspectorSbomBackend:
    """Query-driven Amazon Inspector v2 CycloneDX/SPDX SBOM export backend.

    Supports two explicit operating modes:
    1. **Read-only mode (default):** Consumes an existing Inspector2 ``report_id`` via
       ``GetSbomExport`` and streams exported SBOM JSON/JSON.GZ files from S3.
    2. **Opt-in on-demand export (``trigger_export=True``):** Triggers ``CreateSbomExport``,
       polls ``GetSbomExport`` with bounded backoff, and indexes the resulting S3 export prefix.
    """

    def __init__(
        self,
        *,
        report_id: str | None = None,
        trigger_export: bool = False,
        s3_bucket: str | None = None,
        s3_prefix: str = "",
        kms_key_arn: str | None = None,
        expected_bucket_owner: str | None = None,
        report_format: str = "CYCLONEDX_1_4",
        account_ids: Sequence[str] = (),
        resource_types: Sequence[str] = (),
        ecr_repositories: Sequence[str] = (),
        lambda_functions: Sequence[str] = (),
        wait_for_completion: bool = True,
        poll_interval_seconds: float = 5.0,
        poll_timeout_seconds: float = 300.0,
        region_name: str | None = None,
        profile_name: str | None = None,
        role_arn: str | None = None,
        external_id: str | None = None,
        role_session_name: str = "zerobom-inspector-sbom",
        endpoint_url: str | None = None,
        s3_endpoint_url: str | None = None,
        allow_insecure_http: bool = False,
        suffixes: Sequence[str] = DEFAULT_SBOM_SUFFIXES,
        max_objects: int = 500,
        max_pages: int = 50,
        max_sbom_bytes: int = MAX_SBOM_FILE_BYTES,
        max_concurrency: int = 8,
        max_retries: int = 3,
        timeout_seconds: float = DEFAULT_API_TIMEOUT_SECONDS,
        skip_archived: bool = True,
        strict: bool = False,
        inspector_client: Any | None = None,
        s3_client: Any | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        monotonic_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initialize an Amazon Inspector v2 SBOM export inventory backend."""
        if not isinstance(trigger_export, bool):
            raise BackendConfigError("Configuration option 'trigger_export' must be a bool.")
        if not isinstance(wait_for_completion, bool):
            raise BackendConfigError("Configuration option 'wait_for_completion' must be a bool.")
        if not isinstance(skip_archived, bool):
            raise BackendConfigError("Configuration option 'skip_archived' must be a bool.")
        if not isinstance(strict, bool):
            raise BackendConfigError("Configuration option 'strict' must be a bool.")

        if report_id is not None and trigger_export:
            raise BackendConfigError(
                "Specify either 'report_id' (read-only) or 'trigger_export=True', not both."
            )
        if report_id is None and not trigger_export:
            raise BackendConfigError(
                "AwsInspectorSbomBackend requires either 'report_id' (read-only) or "
                "'trigger_export=True' with 's3_bucket'."
            )

        self._report_id: str | None = None
        if report_id is not None:
            cleaned_rid = validate_no_control_chars(
                report_id, field_name="report_id", max_length=128
            )
            if not _REPORT_ID_RE.fullmatch(cleaned_rid):
                raise BackendConfigError(f"Invalid Inspector2 report_id: {report_id!r}.")
            self._report_id = cleaned_rid

        self._trigger_export = trigger_export
        self._s3_bucket: str | None = (
            validate_s3_bucket(s3_bucket) if s3_bucket is not None else None
        )
        self._s3_prefix = validate_s3_prefix(s3_prefix)
        self._kms_key_arn = validate_aws_kms_key_arn(kms_key_arn)
        self._expected_bucket_owner = (
            validate_aws_account_id(expected_bucket_owner, field_name="expected_bucket_owner")
            if expected_bucket_owner is not None
            else None
        )

        cleaned_fmt = validate_no_control_chars(
            report_format, field_name="report_format", max_length=32
        ).upper()
        if cleaned_fmt not in _VALID_REPORT_FORMATS:
            raise BackendConfigError(
                f"Invalid Inspector2 report_format {report_format!r}; "
                f"expected one of {sorted(_VALID_REPORT_FORMATS)}."
            )
        self._report_format = cleaned_fmt

        if self._trigger_export and self._s3_bucket is None:
            raise BackendConfigError(
                "AwsInspectorSbomBackend requires 's3_bucket' when trigger_export=True."
            )

        self._account_ids = validate_aws_account_ids(account_ids)
        validated_rtypes: list[str] = []
        for rt in resource_types:
            cleaned_rt = validate_no_control_chars(
                rt, field_name="resource_types", max_length=64
            ).upper()
            if cleaned_rt not in _VALID_INSPECTOR_RESOURCE_TYPES:
                raise BackendConfigError(
                    f"Invalid Inspector2 resource_type {rt!r}; "
                    f"expected one of {sorted(_VALID_INSPECTOR_RESOURCE_TYPES)}."
                )
            validated_rtypes.append(cleaned_rt)
        self._resource_types = tuple(validated_rtypes)

        self._ecr_repositories = tuple(
            validate_no_control_chars(repo, field_name="ecr_repositories", max_length=256)
            for repo in ecr_repositories
        )
        self._lambda_functions = tuple(
            validate_no_control_chars(fn, field_name="lambda_functions", max_length=256)
            for fn in lambda_functions
        )

        if (
            isinstance(poll_interval_seconds, bool)
            or not isinstance(poll_interval_seconds, (int, float))
            or not 0.05 <= float(poll_interval_seconds) <= 60.0
        ):
            raise BackendConfigError(
                "Configuration option 'poll_interval_seconds' must be between 0.05 and 60.0."
            )
        if (
            isinstance(poll_timeout_seconds, bool)
            or not isinstance(poll_timeout_seconds, (int, float))
            or not 1.0 <= float(poll_timeout_seconds) <= 1800.0
        ):
            raise BackendConfigError(
                "Configuration option 'poll_timeout_seconds' must be between 1.0 and 1800.0."
            )

        self._wait_for_completion = wait_for_completion
        self._poll_interval_seconds = float(poll_interval_seconds)
        self._poll_timeout_seconds = float(poll_timeout_seconds)
        self._region_name = validate_aws_region(region_name)
        self._profile_name = (
            validate_no_control_chars(profile_name, field_name="profile_name", max_length=128)
            if profile_name is not None
            else None
        )
        self._suffixes = tuple(
            validate_no_control_chars(s, field_name="suffixes", max_length=32).lower()
            for s in suffixes
        )
        self._max_objects = validate_bounded_int(
            max_objects, field_name="max_objects", min_value=1, max_value=10000
        )
        self._max_pages = validate_bounded_int(
            max_pages, field_name="max_pages", min_value=1, max_value=500
        )
        self._max_sbom_bytes = validate_bounded_int(
            max_sbom_bytes,
            field_name="max_sbom_bytes",
            min_value=1024,
            max_value=200 * 1024 * 1024,
        )
        self._max_concurrency = validate_bounded_int(
            max_concurrency, field_name="max_concurrency", min_value=1, max_value=32
        )
        self._max_retries = validate_bounded_int(
            max_retries, field_name="max_retries", min_value=0, max_value=10
        )
        self._timeout_seconds = validate_timeout_seconds(timeout_seconds)
        self._skip_archived = skip_archived
        self._strict = strict
        self._sleep_fn = sleep_fn
        self._monotonic_fn = monotonic_fn
        self._index: InMemoryComponentIndex | None = None

        if inspector_client is not None:
            self._inspector_client = inspector_client
            self._owns_inspector_client = False
        else:
            self._inspector_client = build_aws_client(
                "inspector2",
                region_name=self._region_name,
                profile_name=self._profile_name,
                role_arn=role_arn,
                external_id=external_id,
                role_session_name=role_session_name,
                endpoint_url=endpoint_url,
                allow_insecure_http=allow_insecure_http,
                timeout_seconds=self._timeout_seconds,
                max_retries=self._max_retries,
            )
            self._owns_inspector_client = True

        if s3_client is not None:
            self._s3_client = s3_client
            self._owns_s3_client = False
        else:
            self._s3_client = build_aws_client(
                "s3",
                region_name=self._region_name,
                profile_name=self._profile_name,
                role_arn=role_arn,
                external_id=external_id,
                role_session_name=role_session_name,
                endpoint_url=s3_endpoint_url or endpoint_url,
                allow_insecure_http=allow_insecure_http,
                timeout_seconds=self._timeout_seconds,
                max_retries=self._max_retries,
                max_pool_connections=max(10, self._max_concurrency + 2),
            )
            self._owns_s3_client = True

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> AwsInspectorSbomBackend:
        """Instantiate :class:`AwsInspectorSbomBackend` from CLI options or YAML/JSON config."""
        reject_unknown_config_keys(config, _ALLOWED_CONFIG_KEYS, backend_name="aws_inspector_sbom")
        region = resolve_env_aws_region(
            parse_optional_str_opt(config, "region_name", max_length=64)
        )
        raw_suffixes = parse_str_list_opt(config, "suffixes", max_items=20, max_item_length=32)

        return cls(
            report_id=parse_optional_str_opt(config, "report_id", max_length=128),
            trigger_export=parse_bool_opt(config, "trigger_export", default=False),
            s3_bucket=parse_optional_str_opt(config, "s3_bucket", max_length=63),
            s3_prefix=parse_optional_str_opt(config, "s3_prefix", max_length=1024, allow_empty=True)
            or "",
            kms_key_arn=parse_optional_str_opt(config, "kms_key_arn", max_length=512),
            expected_bucket_owner=parse_optional_str_opt(
                config, "expected_bucket_owner", max_length=12
            ),
            report_format=parse_optional_str_opt(config, "report_format", max_length=32)
            or "CYCLONEDX_1_4",
            account_ids=parse_str_list_opt(
                config, "account_ids", max_items=100, max_item_length=12
            ),
            resource_types=parse_str_list_opt(
                config, "resource_types", max_items=10, max_item_length=64
            ),
            ecr_repositories=parse_str_list_opt(
                config, "ecr_repositories", max_items=50, max_item_length=256
            ),
            lambda_functions=parse_str_list_opt(
                config, "lambda_functions", max_items=50, max_item_length=256
            ),
            wait_for_completion=parse_bool_opt(config, "wait_for_completion", default=True),
            poll_interval_seconds=parse_float_opt(
                config, "poll_interval_seconds", default=5.0, min_value=0.05, max_value=60.0
            ),
            poll_timeout_seconds=parse_float_opt(
                config, "poll_timeout_seconds", default=300.0, min_value=1.0, max_value=1800.0
            ),
            region_name=region,
            profile_name=parse_optional_str_opt(config, "profile_name", max_length=128),
            role_arn=parse_optional_str_opt(config, "role_arn", max_length=512),
            external_id=parse_optional_str_opt(config, "external_id", max_length=1224),
            role_session_name=parse_optional_str_opt(config, "role_session_name", max_length=64)
            or "zerobom-inspector-sbom",
            endpoint_url=parse_optional_str_opt(
                config, "endpoint_url", max_length=MAX_API_URL_LENGTH
            ),
            s3_endpoint_url=parse_optional_str_opt(
                config, "s3_endpoint_url", max_length=MAX_API_URL_LENGTH
            ),
            allow_insecure_http=parse_bool_opt(config, "allow_insecure_http", default=False),
            suffixes=raw_suffixes or DEFAULT_SBOM_SUFFIXES,
            max_objects=parse_int_opt(
                config, "max_objects", default=500, min_value=1, max_value=10000
            ),
            max_pages=parse_int_opt(config, "max_pages", default=50, min_value=1, max_value=500),
            max_sbom_bytes=parse_int_opt(
                config,
                "max_sbom_bytes",
                default=MAX_SBOM_FILE_BYTES,
                min_value=1024,
                max_value=200 * 1024 * 1024,
            ),
            max_concurrency=parse_int_opt(
                config, "max_concurrency", default=8, min_value=1, max_value=32
            ),
            max_retries=parse_int_opt(config, "max_retries", default=3, min_value=0, max_value=10),
            timeout_seconds=parse_float_opt(
                config,
                "timeout_seconds",
                default=DEFAULT_API_TIMEOUT_SECONDS,
                min_value=0.5,
                max_value=120.0,
            ),
            skip_archived=parse_bool_opt(config, "skip_archived", default=True),
            strict=parse_bool_opt(config, "strict", default=False),
        )

    @property
    def name(self) -> str:
        """Registered backend plugin identifier (``"aws_inspector_sbom"``)."""
        return "aws_inspector_sbom"

    def close(self) -> None:
        """Close internally managed boto3 Inspector2 and S3 clients."""
        if self._owns_inspector_client:
            close_fn = getattr(self._inspector_client, "close", None)
            if callable(close_fn):
                close_fn()
        if self._owns_s3_client:
            close_fn = getattr(self._s3_client, "close", None)
            if callable(close_fn):
                close_fn()

    def __repr__(self) -> str:
        """Return a safe summary of the Inspector2 SBOM backend configuration."""
        return (
            f"AwsInspectorSbomBackend(report_id={self._report_id!r}, "
            f"trigger_export={self._trigger_export}, s3_bucket={self._s3_bucket!r})"
        )

    def _build_resource_filter_criteria(self) -> dict[str, Any] | None:
        """Build Inspector2 ``resourceFilterCriteria`` payload from configured filters."""
        criteria: dict[str, Any] = {}
        if self._account_ids:
            criteria["accountId"] = [
                {"comparison": "EQUALS", "value": acc} for acc in self._account_ids
            ]
        if self._resource_types:
            criteria["resourceType"] = [
                {"comparison": "EQUALS", "value": rt} for rt in self._resource_types
            ]
        if self._ecr_repositories:
            criteria["ecrRepositoryName"] = [
                {"comparison": "EQUALS", "value": repo} for repo in self._ecr_repositories
            ]
        if self._lambda_functions:
            criteria["lambdaFunctionName"] = [
                {"comparison": "EQUALS", "value": fn} for fn in self._lambda_functions
            ]
        return criteria or None

    def _create_export_report(self) -> str:
        """Initiate an asynchronous Inspector2 S3 SBOM export job and return ``reportId``."""
        if self._s3_bucket is None:
            raise BackendConfigError("AwsInspectorSbomBackend requires 's3_bucket' for export.")
        s3_dest: dict[str, Any] = {"bucketName": self._s3_bucket}
        if self._s3_prefix:
            s3_dest["keyPrefix"] = self._s3_prefix
        if self._kms_key_arn is not None:
            s3_dest["kmsKeyArn"] = self._kms_key_arn
        if self._expected_bucket_owner is not None:
            s3_dest["expectedBucketOwner"] = self._expected_bucket_owner

        kwargs: dict[str, Any] = {
            "reportFormat": self._report_format,
            "s3Destination": s3_dest,
        }
        filter_criteria = self._build_resource_filter_criteria()
        if filter_criteria is not None:
            kwargs["resourceFilterCriteria"] = filter_criteria

        try:
            resp = self._inspector_client.create_sbom_export(**kwargs)
        except (ClientError, BotoCoreError) as exc:
            raise BackendQueryError(
                f"[{self.name}] Inspector2 CreateSbomExport failed: {exc}"
            ) from exc

        report_id = clean_optional_str(resp.get("reportId"))
        if report_id is None:
            raise BackendQueryError(
                f"[{self.name}] Inspector2 CreateSbomExport response omitted reportId."
            )
        return report_id

    def _poll_export_until_ready(self, report_id: str) -> dict[str, Any]:
        """Poll ``GetSbomExport`` with bounded backoff until terminal status or timeout."""
        deadline = self._monotonic_fn() + self._poll_timeout_seconds
        attempt = 0

        while True:
            try:
                resp = self._inspector_client.get_sbom_export(reportId=report_id)
            except (ClientError, BotoCoreError) as exc:
                raise BackendQueryError(
                    f"[{self.name}] Inspector2 GetSbomExport failed for {report_id!r}: {exc}"
                ) from exc

            status = (clean_optional_str(resp.get("status")) or "").upper()
            if status in {"SUCCEEDED", "FAILED", "CANCELLED"}:
                return dict(resp)

            if status != "IN_PROGRESS":
                raise BackendQueryError(
                    f"[{self.name}] Unexpected Inspector2 GetSbomExport status {status!r} "
                    f"for report {report_id!r}."
                )

            if not self._wait_for_completion:
                raise BackendQueryError(
                    f"[{self.name}] Inspector2 report {report_id!r} is still IN_PROGRESS and "
                    "wait_for_completion=False."
                )

            remaining = deadline - self._monotonic_fn()
            if remaining <= 0:
                raise BackendQueryError(
                    f"[{self.name}] Timed out after {self._poll_timeout_seconds}s waiting for "
                    f"Inspector2 export {report_id!r}."
                )

            delay = min(
                self._poll_interval_seconds * (1.5**attempt),
                _MAX_POLL_INTERVAL_SECONDS,
                remaining,
            )
            self._sleep_fn(delay)
            attempt += 1

    def load(self) -> int:
        """Resolve Inspector2 SBOM export state and index exported CycloneDX/SPDX S3 objects."""
        active_report_id = self._report_id or self._create_export_report()
        export_resp = self._poll_export_until_ready(active_report_id)
        status = (clean_optional_str(export_resp.get("status")) or "").upper()

        if status == "FAILED":
            error_code = (clean_optional_str(export_resp.get("errorCode")) or "").upper()
            if error_code == "NO_FINDINGS_FOUND":
                self._index = InMemoryComponentIndex()
                return 0
            error_msg = clean_optional_str(export_resp.get("errorMessage")) or "export failed"
            raise BackendQueryError(
                f"[{self.name}] Inspector2 export {active_report_id!r} FAILED "
                f"({error_code or 'UNKNOWN'}): {error_msg}"
            )

        if status != "SUCCEEDED":
            raise BackendQueryError(
                f"[{self.name}] Inspector2 export {active_report_id!r} ended in status {status!r}."
            )

        s3_dest = export_resp.get("s3Destination")
        if not isinstance(s3_dest, Mapping):
            raise BackendQueryError(
                f"[{self.name}] Inspector2 SUCCEEDED export {active_report_id!r} "
                "omitted s3Destination."
            )

        raw_bucket = clean_optional_str(s3_dest.get("bucketName"))
        if raw_bucket is None:
            raise BackendQueryError(
                f"[{self.name}] Inspector2 export {active_report_id!r} omitted bucketName."
            )
        dest_bucket = validate_s3_bucket(raw_bucket)
        dest_prefix = validate_s3_prefix(clean_optional_str(s3_dest.get("keyPrefix")) or "")
        dest_owner = (
            validate_aws_account_id(
                clean_optional_str(s3_dest.get("expectedBucketOwner")) or "",
                field_name="expectedBucketOwner",
            )
            if clean_optional_str(s3_dest.get("expectedBucketOwner")) is not None
            else self._expected_bucket_owner
        )

        self._index = load_s3_sbom_prefix(
            self._s3_client,
            bucket=dest_bucket,
            prefix=dest_prefix,
            suffixes=self._suffixes,
            backend_name=self.name,
            max_objects=self._max_objects,
            max_pages=self._max_pages,
            max_sbom_bytes=self._max_sbom_bytes,
            strict=self._strict,
            skip_archived=self._skip_archived,
            expected_bucket_owner=dest_owner,
            max_concurrency=self._max_concurrency,
            extra_base_metadata={"inspector_report_id": active_report_id},
        )
        return len(self._index.components)

    def find_components(self, queries: Sequence[PackageQuery]) -> tuple[InventoryComponent, ...]:
        """Search indexed Inspector2 SBOM components for package matches."""
        if not queries:
            return ()
        if self._index is None:
            self.load()
        if self._index is None:
            return ()
        return self._index.find_components(queries)
