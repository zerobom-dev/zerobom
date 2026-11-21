# zerobom-azure

Microsoft Azure inventory backend plugins for [`zerobom`](https://github.com/zerobom-dev/zerobom), integrating via standard `zerobom.backends` entry points:

- **`azure_resource_graph`**: Queries Microsoft Defender for Cloud / Azure Resource Graph (`microsoft.security/softwareinventories`) via parameterized KQL queries and `skipToken` pagination.
- **`azure_blob_sbom`**: Streams CycloneDX (1.4–1.6) and SPDX (2.2–2.3) JSON SBOMs from Azure Blob Storage containers.

## Installation

```bash
# With bearer token (ZEROBOM_AZURE_TOKEN) or SAS token (ZEROBOM_AZURE_SAS_TOKEN):
uvx "zerobom[azure]" scan --osv advisory.osv.json --backend azure_resource_graph --backend-opt subscriptions=00000000-0000-0000-0000-000000000000

# Or include azure-identity for DefaultAzureCredential (use_default_credential=true):
pip install "zerobom-azure[identity]"
```

## Usage Examples

### Azure Resource Graph (`azure_resource_graph`)

```bash
zerobom scan \
  --osv advisory.osv.json \
  --backend azure_resource_graph \
  --backend-opt subscriptions=11111111-1111-1111-1111-111111111111 \
  --backend-opt use_default_credential=true \
  --format sarif > results.sarif
```

Least-privilege RBAC role: **Reader** (plus **Security Reader** on target subscriptions).

### Azure Blob Storage SBOM Prefix (`azure_blob_sbom`)

```bash
zerobom scan \
  --osv advisory.osv.json \
  --backend azure_blob_sbom \
  --backend-opt account_name=corpsbomstore \
  --backend-opt container=sboms \
  --backend-opt prefix=prod/ \
  --backend-opt use_default_credential=true
```

Least-privilege RBAC role: **Storage Blob Data Reader**.

## Documentation & License

- Documentation: https://zerobom.dev/backends/
- License: Apache-2.0
