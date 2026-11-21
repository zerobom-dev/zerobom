# GitHub Action & CI Integration

The repository includes a composite GitHub Action (`action.yml`) designed for scheduled pre-CVE blog monitoring, deterministic OSV scanning against repository SBOMs, GitHub Code Scanning SARIF upload, and idempotent GitHub Issue deduplication.

## Quick Workflow Example

```yaml
name: zerobom Pre-CVE Watch
on:
  schedule:
    - cron: "0 */6 * * *"
  workflow_dispatch:

permissions:
  contents: read
  security-events: write
  issues: write

jobs:
  zerobom-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: zerobom-dev/zerobom@v0.1.0
        with:
          mode: watch
          sbom: sbom.cdx.json
          upload-sarif: "true"
          create-github-issues: "true"
          llm-base-url: ${{ secrets.ZEROBOM_LLM_BASE_URL }}
          llm-model: ${{ secrets.ZEROBOM_LLM_MODEL }}
          llm-api-key: ${{ secrets.ZEROBOM_LLM_API_KEY }}
```

## Key Security & Reliability Controls in `action.yml`

- **Zero script injection:** All inputs pass strictly through `env:` variables (`ZB_*`), never interpolated directly into shell `run:` commands.
- **Separated SQLite state vs. ephemeral reports:** SQLite state caches under `.zerobom/state` via `actions/cache/restore@v4` and `actions/cache/save@v4` (`!cancelled()`), while fresh JSON/SARIF artifacts write under `.zerobom-reports/` after cleaning stale files.
- **Pluggable backends & extras:** Configure `backend`, multi-line `backend-opts`, and `extras` (e.g., `aws`) transparently via `uvx`.

## SARIF 2.1.0 & Idempotent GitHub Issues

- **SARIF Code Scanning ([`outputs.sarif`](api/outputs.md)):** Emits SARIF 2.1.0 with `tool.driver.rules[]`, numeric `security-severity`, repo-relative SBOM URIs (and normalized scheme-stripped logical paths for remote backends, never exposing local host absolute paths in `assetId`), and isolated `partialFingerprints` so remote container/cloud hits never overwrite each other.
- **GitHub Issue Sync ([`GitHubIssueSyncer`](api/outputs.md)):** Creates or updates at most one open issue per advisory using sanitized HTML comment markers (`<!-- zerobom:advisory-id:PRECVE-... -->`), escapes HTML/XSS/Markdown images/`@mentions`, ignores pull requests returned by `/issues`, and fails closed if open issue pagination exceeds bounds before creating duplicates.
