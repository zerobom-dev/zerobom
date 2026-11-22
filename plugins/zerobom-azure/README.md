# zerobom-azure

Microsoft Azure inventory backend plugins for [`zerobom`](https://github.com/zerobom-dev/zerobom), integrating via standard `zerobom.backends` entry points:

- **`azure_resource_graph`**: Queries Microsoft Defender for Cloud / Azure Resource Graph (`microsoft.security/softwareinventories`) across `subscriptions`, `management_groups`, or `tenant_scope=true` with quota-aware `$skipToken` pacing, `osPlatform` distro mapping, and sovereign cloud presets (`commercial`, `usgov`, `china`).
- **`azure_blob_sbom`**: Streams plain or `.gz`-compressed CycloneDX (1.4–1.6) and SPDX (2.2–2.3) JSON SBOMs concurrently from Azure Blob Storage containers while skipping `Archive`-tier blobs cleanly.

> **Coverage note:** `azure_resource_graph` (`microsoft.security/softwareinventories`) covers VM and Arc-enabled server software inventories via Defender TVM; pair it with `oci_sbom` (for ACR container images) or `azure_blob_sbom` for exported container SBOMs.

## Installation

```bash
uvx "zerobom[azure]" scan --osv advisory.osv.json --backend azure_resource_graph --backend-opt subscriptions=00000000-0000-0000-0000-000000000000
```

Or install into an existing project environment:

```bash
pip install "zerobom[azure]"
```

`azure-identity` (`DefaultAzureCredential`) is included directly and refreshes bearer tokens automatically across long-lived `watch` sessions.

## Usage Examples

### Azure Resource Graph (`azure_resource_graph`)

```bash
zerobom scan \
  --osv advisory.osv.json \
  --backend azure_resource_graph \
  --backend-opt subscriptions=11111111-1111-1111-1111-111111111111 \
  --format sarif > results.sarif
```

Scope options (mutually exclusive):
- `--backend-opt subscriptions=<guid>` (or `ZEROBOM_AZURE_SUBSCRIPTION_ID`)
- `--backend-opt management_groups=<mg-id>`
- `--backend-opt tenant_scope=true`

Authentication priority:
1. Explicit `access_token` option
2. `ZEROBOM_AZURE_ACCESS_TOKEN` or `ZEROBOM_AZURE_TOKEN`
3. Automatic `DefaultAzureCredential` (disable fallback with `--backend-opt use_default_credential=false`)

Least-privilege RBAC role: **Reader** (plus **Security Reader** on target subscriptions/management groups).

### Azure Blob Storage SBOM Prefix (`azure_blob_sbom`)

```bash
zerobom scan \
  --osv advisory.osv.json \
  --backend azure_blob_sbom \
  --backend-opt account_name=corpsbomstore \
  --backend-opt container=sboms \
  --backend-opt prefix=prod/
```

Supports Entra bearer auth (`DefaultAzureCredential` / token env vars) or SAS tokens (`sas_token` / `ZEROBOM_AZURE_SAS_TOKEN`, preserving literal `+` characters in `sig=`).

Least-privilege RBAC role: **Storage Blob Data Reader**.

## Documentation & License

- Documentation: https://zerobom.dev/backends/
- License: Apache-2.0
