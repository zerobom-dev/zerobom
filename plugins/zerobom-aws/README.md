# zerobom-aws

AWS inventory backend plugins for [`zerobom`](https://github.com/zerobom-dev/zerobom), integrating via standard `zerobom.backends` entry points:

- **`aws_security_hub`**: Queries AWS Security Hub `GetSoftwareV2` and `GetSoftwareResourcesV2` software inventory without exporting or mutating security findings.
- **`s3_sbom`**: Streams CycloneDX (1.4–1.6) and SPDX (2.2–2.3) JSON SBOMs from an Amazon S3 bucket prefix with size, page, and traversal guards.

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
  --format sarif > results.sarif
```

Least-privilege read-only IAM actions required:
- `securityhub:GetSoftwareV2`
- `securityhub:GetSoftwareResourcesV2`

### Amazon S3 SBOM Prefix (`s3_sbom`)

```bash
zerobom scan \
  --osv advisory.osv.json \
  --backend s3_sbom \
  --backend-opt bucket=corp-sbom-archive \
  --backend-opt prefix=prod/ \
  --backend-opt region_name=us-east-1
```

Least-privilege read-only IAM actions required:
- `s3:ListBucket`
- `s3:GetObject`

## Documentation & License

- Documentation: https://zerobom.dev/backends/
- License: Apache-2.0
