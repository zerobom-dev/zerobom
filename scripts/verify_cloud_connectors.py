"""Opt-in read-only live cloud sandbox verification script for pre-release checks.

This script never runs inside automated unit tests or CI. Run manually with read-only
IAM/RBAC credentials in your own AWS, GCP, and/or Azure sandboxes before tagging
``plugins-v0.1.0``.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass

from zerobom.models import PackageQuery
from zerobom_aws import AwsInspectorSbomBackend, AwsSecurityHubBackend, S3SbomBackend
from zerobom_azure import AzureBlobSbomBackend, AzureResourceGraphBackend
from zerobom_gcp import GcpArtifactAnalysisBackend, GcsSbomBackend

_PROBE_QUERY = (
    PackageQuery(
        canonical_purl="pkg:pypi/requests",
        ecosystem="pypi",
        osv_ecosystem="PyPI",
        name="requests",
    ),
)


@dataclass(frozen=True)
class CheckOutcome:
    """Structured result from one opt-in live cloud verification probe."""

    name: str
    status: str
    detail: str


def _probe_aws() -> list[CheckOutcome]:
    """Run read-only live checks against configured AWS Security Hub / Inspector2 / S3 targets."""
    outcomes: list[CheckOutcome] = []
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
    role_arn = os.environ.get("ZEROBOM_LIVE_AWS_ROLE_ARN")

    try:
        sh = AwsSecurityHubBackend(
            region_name=region,
            role_arn=role_arn,
            max_results=10,
            max_pages=1,
            max_software_entries=5,
        )
        try:
            hits = sh.find_components(_PROBE_QUERY)
            outcomes.append(
                CheckOutcome("aws_security_hub", "PASS", f"queried {region}, hits={len(hits)}")
            )
        finally:
            sh.close()
    except Exception as exc:
        outcomes.append(CheckOutcome("aws_security_hub", "FAIL", str(exc)))

    bucket = os.environ.get("ZEROBOM_LIVE_AWS_S3_BUCKET")
    if bucket:
        prefix = os.environ.get("ZEROBOM_LIVE_AWS_S3_PREFIX", "")
        try:
            s3 = S3SbomBackend(
                bucket=bucket,
                prefix=prefix,
                region_name=region,
                role_arn=role_arn,
                max_objects=10,
                max_pages=2,
            )
            try:
                loaded = s3.load()
                if "aws_secret" in repr(s3):
                    outcomes.append(CheckOutcome("s3_sbom", "FAIL", "Unexpected secret in repr()"))
                else:
                    outcomes.append(
                        CheckOutcome(
                            "s3_sbom", "PASS", f"bucket={bucket}, indexed_components={loaded}"
                        )
                    )
            finally:
                s3.close()
        except Exception as exc:
            outcomes.append(CheckOutcome("s3_sbom", "FAIL", str(exc)))
    else:
        outcomes.append(
            CheckOutcome("s3_sbom", "SKIP", "Set ZEROBOM_LIVE_AWS_S3_BUCKET to verify S3 SBOMs.")
        )

    report_id = os.environ.get("ZEROBOM_LIVE_AWS_INSPECTOR_REPORT_ID")
    if report_id:
        try:
            insp = AwsInspectorSbomBackend(
                report_id=report_id,
                region_name=region,
                role_arn=role_arn,
                max_objects=10,
                max_pages=2,
            )
            try:
                loaded = insp.load()
                outcomes.append(
                    CheckOutcome(
                        "aws_inspector_sbom",
                        "PASS",
                        f"report_id={report_id}, indexed_components={loaded}",
                    )
                )
            finally:
                insp.close()
        except Exception as exc:
            outcomes.append(CheckOutcome("aws_inspector_sbom", "FAIL", str(exc)))
    else:
        outcomes.append(
            CheckOutcome(
                "aws_inspector_sbom",
                "SKIP",
                "Set ZEROBOM_LIVE_AWS_INSPECTOR_REPORT_ID to check read-only Inspector2.",
            )
        )

    return outcomes


def _probe_gcp() -> list[CheckOutcome]:
    """Run read-only live checks against configured GCP Artifact Analysis and GCS targets."""
    outcomes: list[CheckOutcome] = []
    project_id = os.environ.get("ZEROBOM_LIVE_GCP_PROJECT_ID") or os.environ.get(
        "ZEROBOM_GCP_PROJECT_ID"
    )
    location = os.environ.get("ZEROBOM_LIVE_GCP_LOCATION")

    if project_id:
        for mode in ("package", "sbom_reference"):
            label = f"gcp_artifact_analysis[{mode}]"
            try:
                aa = GcpArtifactAnalysisBackend(
                    project_id=project_id,
                    location=location,
                    mode=mode,
                    page_size=20,
                    max_pages=2,
                )
                try:
                    hits = aa.find_components(_PROBE_QUERY)
                    outcomes.append(
                        CheckOutcome(label, "PASS", f"project={project_id}, hits={len(hits)}")
                    )
                finally:
                    aa.close()
            except Exception as exc:
                outcomes.append(CheckOutcome(label, "FAIL", str(exc)))
    else:
        outcomes.append(
            CheckOutcome(
                "gcp_artifact_analysis",
                "SKIP",
                "Set ZEROBOM_LIVE_GCP_PROJECT_ID (or ZEROBOM_GCP_PROJECT_ID) to verify GCP.",
            )
        )

    bucket = os.environ.get("ZEROBOM_LIVE_GCP_GCS_BUCKET")
    if bucket:
        prefix = os.environ.get("ZEROBOM_LIVE_GCP_GCS_PREFIX", "")
        try:
            gcs = GcsSbomBackend(bucket=bucket, prefix=prefix, max_objects=10, max_pages=2)
            try:
                loaded = gcs.load()
                outcomes.append(
                    CheckOutcome(
                        "gcs_sbom", "PASS", f"bucket={bucket}, indexed_components={loaded}"
                    )
                )
            finally:
                gcs.close()
        except Exception as exc:
            outcomes.append(CheckOutcome("gcs_sbom", "FAIL", str(exc)))
    else:
        outcomes.append(
            CheckOutcome("gcs_sbom", "SKIP", "Set ZEROBOM_LIVE_GCP_GCS_BUCKET to verify GCS SBOMs.")
        )

    return outcomes


def _probe_azure() -> list[CheckOutcome]:
    """Run read-only live checks against Azure Resource Graph and Azure Blob Storage targets."""
    outcomes: list[CheckOutcome] = []
    sub_id = os.environ.get("ZEROBOM_LIVE_AZURE_SUBSCRIPTION_ID") or os.environ.get(
        "ZEROBOM_AZURE_SUBSCRIPTION_ID"
    )
    mg_id = os.environ.get("ZEROBOM_LIVE_AZURE_MG_ID")
    cloud = os.environ.get("ZEROBOM_LIVE_AZURE_CLOUD", "commercial")

    if sub_id or mg_id:
        try:
            arg = AzureResourceGraphBackend(
                subscriptions=tuple(s.strip() for s in sub_id.split(",") if s.strip())
                if sub_id and not mg_id
                else (),
                management_groups=(mg_id,) if mg_id else (),
                cloud=cloud,
                page_size=20,
                max_pages=2,
            )
            try:
                hits = arg.find_components(_PROBE_QUERY)
                outcomes.append(
                    CheckOutcome("azure_resource_graph", "PASS", f"cloud={cloud}, hits={len(hits)}")
                )
            finally:
                arg.close()
        except Exception as exc:
            outcomes.append(CheckOutcome("azure_resource_graph", "FAIL", str(exc)))
    else:
        outcomes.append(
            CheckOutcome(
                "azure_resource_graph",
                "SKIP",
                "Set ZEROBOM_LIVE_AZURE_SUBSCRIPTION_ID or ZEROBOM_LIVE_AZURE_MG_ID to verify.",
            )
        )

    account = os.environ.get("ZEROBOM_LIVE_AZURE_STORAGE_ACCOUNT")
    container = os.environ.get("ZEROBOM_LIVE_AZURE_STORAGE_CONTAINER")
    if account and container:
        prefix = os.environ.get("ZEROBOM_LIVE_AZURE_STORAGE_PREFIX", "")
        sas = os.environ.get("ZEROBOM_AZURE_SAS_TOKEN")
        try:
            blob = AzureBlobSbomBackend(
                account_name=account,
                container=container,
                prefix=prefix,
                cloud=cloud,
                sas_token=sas,
                max_objects=10,
                max_pages=2,
            )
            try:
                loaded = blob.load()
                if sas and sas in repr(blob):
                    outcomes.append(
                        CheckOutcome("azure_blob_sbom", "FAIL", "SAS token leaked in repr(blob)")
                    )
                else:
                    outcomes.append(
                        CheckOutcome(
                            "azure_blob_sbom",
                            "PASS",
                            f"account={account}/{container}, indexed_components={loaded}",
                        )
                    )
            finally:
                blob.close()
        except Exception as exc:
            outcomes.append(CheckOutcome("azure_blob_sbom", "FAIL", str(exc)))
    else:
        outcomes.append(
            CheckOutcome(
                "azure_blob_sbom",
                "SKIP",
                "Set ZEROBOM_LIVE_AZURE_STORAGE_ACCOUNT and ZEROBOM_LIVE_AZURE_STORAGE_CONTAINER.",
            )
        )

    return outcomes


def main(argv: list[str] | None = None) -> int:
    """Execute read-only live cloud verification probes and return exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cloud",
        choices=("aws", "gcp", "azure", "all"),
        default="all",
        help="Target cloud provider(s) to probe.",
    )
    args = parser.parse_args(argv)

    runners: dict[str, Callable[[], list[CheckOutcome]]] = {
        "aws": _probe_aws,
        "gcp": _probe_gcp,
        "azure": _probe_azure,
    }
    targets = ("aws", "gcp", "azure") if args.cloud == "all" else (args.cloud,)

    all_outcomes: list[CheckOutcome] = []
    for target in targets:
        all_outcomes.extend(runners[target]())

    failures = 0
    for outcome in all_outcomes:
        print(f"[{outcome.status:4s}] {outcome.name}: {outcome.detail}")
        if outcome.status == "FAIL":
            failures += 1

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
