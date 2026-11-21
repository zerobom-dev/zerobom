# Inventory Backends

Core `zerobom` contains **zero cloud provider SDKs**. Every inventory integration implements [`InventoryBackend`](api/backends.md) and is discovered dynamically via Python `zerobom.backends` entry points.

Backends normalize inventory records into `AssetRef` + `InventoryComponent` and return candidates for [`PackageQuery`](api/models.md). All version matching stays inside `zerobom.verify.osv_compiler`.

## Built-In Backends (Core Package)

### `local_sbom` (Default)
Recursively parses CycloneDX (1.4–1.6) and SPDX (2.2–2.3) JSON files or directories with bounded file sizes (`<= 50 MiB`), nesting depth guards, and symlink/root-escape protection.

```bash
zerobom scan --osv advisory.osv.json --sbom ./sboms/
```

### `dependency_track`
Queries OWASP Dependency-Track `/api/v1/component/identity` across projects with version-independent coordinate lookup (`query_mode="coordinates"` default, or `"purl"` opt-in), strict HTTPS/CA/TLS validation, and bounded pagination.

```bash
export ZEROBOM_DT_API_KEY="odt_..."
zerobom scan --osv advisory.osv.json \
  --backend dependency_track \
  --backend-opt base_url=https://dtrack.internal.example.org
```

### `oci_sbom`
Fetches attached CycloneDX/SPDX SBOM artifacts and signed in-toto DSSE envelopes (up to bounded nesting depth `<= 5`) from OCI container registries with multi-arch platform filtering, Bearer realm pinning (`allowed_auth_hosts`), and SSRF-checked blob redirects.

```bash
zerobom scan --osv advisory.osv.json \
  --backend oci_sbom \
  --backend-opt images=ghcr.io/org/service:v1.2.3
```

### `k8s_sbom`
Queries Kubernetes Trivy Operator `sbomreports` and optional `clustersbomreports` CRDs directly from kubeconfig (blocking unsafe `exec` plugins) or in-cluster ServiceAccount tokens.

```bash
zerobom scan --osv advisory.osv.json \
  --backend k8s_sbom \
  --backend-opt namespace=production \
  --backend-opt include_cluster_reports=true
```

---

## Optional Cloud Workspace Plugins

Install only the cloud adapter you need without pulling other cloud SDKs:

| Cloud | Install Extra | Backends | Key Options (`--backend-opt`) |
| --- | --- | --- | --- |
| **AWS** | `zerobom[aws]` | `aws_security_hub`, `s3_sbom` | `region_name`, `account_ids`, `resource_types`, `bucket`, `prefix` |
| **GCP** | `zerobom[gcp]` (+ `[adc]`) | `gcp_artifact_analysis`, `gcs_sbom` | `project_id`, `resource_uri_prefix`, `bucket`, `prefix`, `use_adc` |
| **Azure** | `zerobom[azure]` (+ `[identity]`) | `azure_resource_graph`, `azure_blob_sbom` | `subscriptions`, `account_name`, `container`, `prefix`, `use_default_credential` |

### Least-Privilege Cloud Scopes

- **AWS (`zerobom-aws`):** `securityhub:GetSoftwareV2`, `securityhub:GetSoftwareResourcesV2`, and `s3:ListBucket` + `s3:GetObject`.
- **GCP (`zerobom-gcp`):** `roles/containeranalysis.occurrences.viewer` and `roles/storage.objectViewer`.
- **Azure (`zerobom-azure`):** `Reader` + `Security Reader` on target subscriptions, and `Storage Blob Data Reader` for Blob SBOM prefixes.

## Plugin Code-Execution Trust Boundary

`zerobom.backends` plugins load dynamically via Python `importlib.metadata` entry points and execute in-process with the full privileges of the `zerobom` CLI/worker (plugins are **not** sandboxed). Install third-party backend packages only from trusted publishers.

For building your own enterprise or internal inventory plugin, see the [Plugin Authoring Guide](PLUGIN_AUTHORING.md).
