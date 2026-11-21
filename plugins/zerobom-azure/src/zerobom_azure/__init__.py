"""Azure inventory backend plugins for ``zerobom``."""

from zerobom_azure.blob_sbom import AzureBlobSbomBackend
from zerobom_azure.resource_graph import AzureResourceGraphBackend

__all__ = [
    "AzureBlobSbomBackend",
    "AzureResourceGraphBackend",
]
