# zerobom-gcp

Google Cloud Platform inventory backend plugins for [`zerobom`](https://github.com/zerobom-dev/zerobom), integrating via standard `zerobom.backends` entry points:

- **`gcp_artifact_analysis`**: Queries GCP Container Analysis / Artifact Analysis occurrences (`kind="PACKAGE"` and/or `kind="SBOM_REFERENCE"` with SHA-256 verified GCS SBOM resolution), supporting global and regional (`location=...`) endpoints, CPE 2.2/2.3 OS distro resolution, and safe CEL filtering.
- **`gcs_sbom`**: Streams plain or `.gz`-compressed CycloneDX (1.4–1.6) and SPDX (2.2–2.3) JSON SBOMs concurrently from Google Cloud Storage prefixes (including Requester Pays via `user_project=...`).

## Installation

```bash
uvx "zerobom[gcp]" scan --osv advisory.osv.json --backend gcp_artifact_analysis --backend-opt project_id=my-gcp-project
```

Or install into an existing project environment:

```bash
pip install "zerobom[gcp]"
```

Application Default Credentials (`google-auth[requests]`) are included by default and refresh automatically across long-lived `watch` sessions.

## Usage Examples

### GCP Artifact Analysis (`gcp_artifact_analysis`)

```bash
zerobom scan \
  --osv advisory.osv.json \
  --backend gcp_artifact_analysis \
  --backend-opt project_id=my-prod-project \
  --backend-opt location=us \
  --backend-opt mode=both \
  --format sarif > results.sarif
```

Authentication priority:
1. Explicit `access_token` option
2. `ZEROBOM_GCP_ACCESS_TOKEN`, `ZEROBOM_GCP_TOKEN`, or `GOOGLE_OAUTH_ACCESS_TOKEN`
3. Automatic Application Default Credentials (disable fallback with `--backend-opt use_adc=false`)

Least-privilege IAM roles:
- `roles/containeranalysis.occurrences.viewer`
- `roles/storage.objectViewer` (when using `mode=sbom_reference` or `mode=both`)

### Google Cloud Storage SBOM Prefix (`gcs_sbom`)

```bash
zerobom scan \
  --osv advisory.osv.json \
  --backend gcs_sbom \
  --backend-opt bucket=corp-sboms \
  --backend-opt prefix=services/
```

Least-privilege IAM role: `roles/storage.objectViewer`.

## Documentation & License

- Documentation: https://zerobom.dev/backends/
- License: Apache-2.0
