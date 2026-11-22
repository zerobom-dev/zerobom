# zerobom-aws

AWS inventory backend plugins for [`zerobom`](https://github.com/zerobom-dev/zerobom), integrating via standard `zerobom.backends` entry points:

- **`aws_security_hub`**: Queries AWS Security Hub `GetSoftwareV2` and `GetSoftwareResourcesV2` software inventory (including AWS Organizations `Scopes` and STS `AssumeRole`) without exporting or mutating security findings.
- **`aws_inspector_sbom`**: Consumes Amazon Inspector v2 CycloneDX 1.4 / SPDX 2.3 SBOM exports from S3 (`report_id=...` read-only by default, or opt-in `trigger_export=true` with bounded polling and EC2/ECR/Lambda asset enrichment).
- **`s3_sbom`**: Streams plain or `.gz`-compressed CycloneDX (1.4–1.6) and SPDX (2.2–2.3) JSON SBOMs from Amazon S3 prefixes with concurrent downloads, Glacier/Deep Archive skipping, bucket-owner validation, and traversal guards.

## Installation

```bash
uvx "zerobom[aws]" scan --osv advisory.osv.json --backend aws_security_hub --backend-opt region_name=us-east-1
```

Or install into an existing project environment:

```bash
pip install "zerobom[aws]"
```

## Usage Examples

### AWS Security Hub v2 (`aws_security_hub`)

```bash
zerobom scan \
  --osv advisory.osv.json \
  --backend aws_security_hub \
  --backend-opt region_name=us-east-1 \
  --backend-opt account_ids=111122223333 \
  --backend-opt organization_id=o-abc1234567 \
  --format sarif > results.sarif
```

Least-privilege read-only IAM actions required:
- `securityhub:GetSoftwareV2`
- `securityhub:GetSoftwareResourcesV2`
- Optional cross-account role: `sts:AssumeRole` (via `role_arn=...`, `external_id=...`)

### Amazon Inspector v2 SBOM (`aws_inspector_sbom`)

**Read-only consumption (default)** using an existing Inspector2 report ID:

```bash
zerobom scan \
  --osv advisory.osv.json \
  --backend aws_inspector_sbom \
  --backend-opt report_id=abc12345-report-id \
  --backend-opt region_name=us-east-1 \
  --backend-opt expected_bucket_owner=111122223333
```

**Opt-in on-demand export (`trigger_export=true`)**:

```bash
zerobom scan \
  --osv advisory.osv.json \
  --backend aws_inspector_sbom \
  --backend-opt trigger_export=true \
  --backend-opt s3_bucket=corp-inspector-sboms \
  --backend-opt kms_key_arn=arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab \
  --backend-opt report_format=CYCLONEDX_1_4 \
  --backend-opt resource_types=AWS_ECR_CONTAINER_IMAGE,AWS_EC2_INSTANCE
```

Least-privilege IAM actions required:
- Read-only mode: `inspector2:GetSbomExport`, `s3:ListBucket`, `s3:GetObject`
- Opt-in export mode: additionally `inspector2:CreateSbomExport` (and `kms:GenerateDataKey` / `kms:Decrypt` for SSE-KMS buckets)

### Amazon S3 SBOM Prefix (`s3_sbom`)

```bash
zerobom scan \
  --osv advisory.osv.json \
  --backend s3_sbom \
  --backend-opt bucket=corp-sbom-archive \
  --backend-opt prefix=prod/ \
  --backend-opt region_name=us-east-1 \
  --backend-opt expected_bucket_owner=111122223333
```

Least-privilege read-only IAM actions required:
- `s3:ListBucket`
- `s3:GetObject`

## Documentation & License

- Documentation: https://zerobom.dev/backends/
- License: Apache-2.0
