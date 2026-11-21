"""GCP inventory backend plugins for ``zerobom``."""

from zerobom_gcp.artifact_analysis import GcpArtifactAnalysisBackend
from zerobom_gcp.gcs_sbom import GcsSbomBackend

__all__ = [
    "GcpArtifactAnalysisBackend",
    "GcsSbomBackend",
]
