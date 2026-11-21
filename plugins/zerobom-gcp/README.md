# zerobom-gcp

Google Cloud Platform inventory backend plugins for [`zerobom`](https://github.com/zerobom-dev/zerobom), integrating via standard `zerobom.backends` entry points:

- **`gcp_artifact_analysis`**: Queries GCP Container Analysis / Artifact Analysis occurrences (`kind="PACKAGE"`) with safe CEL filtering, OS CPE resolution, and paginated lookup.
- **`gcs_sbom`**: Streams CycloneDX (1.4–1.6) and SPDX (2.2–2.3) JSON SBOMs from Google Cloud Storage prefixes.

## Installation

```bash
# With explicit token / Workload Identity token via ZEROBOM_GCP_TOKEN:
uvx "zerobom[gcp]" scan --osv advisory.osv.json --backend gcp_artifact_analysis --backend-opt project_id=my-gcp-project

# Or include google-auth for Application Default Credentials (use_adc=true):
pip install "zerobom-gcp[adc]"
```

## Usage Examples

### GCP Artifact Analysis (`gcp_artifact_analysis`)

```bash
zerobom scan \
  --osv advisory.osv.json \
  --backend gcp_artifact_analysis \
  --backend-opt project_id=my-prod-project \
  --backend-opt use_adc=true \
  --format sarif > results.sarif
```

Authentication options:
- `access_token` / `ZEROBOM_GCP_TOKEN` (direct OAuth bearer token)
- `use_adc=true` with `zerobom-gcp[adc]` (`google-auth`)

Least-privilege IAM role: `roles/containeranalysis.occurrences.viewer`.

### Google Cloud Storage SBOM Prefix (`gcs_sbom`)

```bash
zerobom scan \
  --osv advisory.osv.json \
  --backend gcs_sbom \
  --backend-opt bucket=corp-sboms \
  --backend-opt prefix=services/ \
  --backend-opt use_adc=true
```

Least-privilege IAM role: `roles/storage.objectViewer`.

## Documentation & License

- Documentation: https://zerobom.dev/backends/
- License: Apache-2.0
