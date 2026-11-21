# Changelog

All notable changes to `zerobom` are documented in this file following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-21

### Added
- **Deterministic Verification Engine (`zerobom.verify`):**
  - Deterministic quote grounding (exact/normalized substring match with left/right token boundary guards and colon-list negation filtering).
  - ASCII PackageURL canonicalization, unnamespaced & `generic`-namespace blocklist, Solr-safe Maven/PyPI/npm/Go `HttpRegistryChecker` with TTL SQLite caching and `follow_redirects=False`.
  - Two-axis credibility scorer (`AUTO >= 0.75`, `TRIAGE 0.50-0.74`, `DROP < 0.50`), isolating `TRIAGE`/unbounded/registry-error claims from `AUTO` alerts.
  - OSV 1.6.7-compatible compiler using the non-official local namespace `PRECVE-YYYY-XXXXXXXX` (with `Generic` and `CloudLinux` documented as `zerobom` extensions) and deterministic `univers` version evaluation.
- **Ingestion & Narrow LLM Layer (`zerobom.ingest`, `zerobom.extract`):**
  - SSRF-hardened `SafeHttpFetcher` (DNS validation per hop, `<= 3` redirects, bounded streaming bytes, `Content-Type` allowlist).
  - RSS, Atom, XML sitemap, and HTML index pollers + SQLite ETag/SHA-256 deduplication store.
  - Pre-LLM keyword/regex prefilter preserving pre-CVE alias disclosures (`known_aliases`).
  - Isolated `Extractor` protocol and `OpenAICompatExtractor` (`httpx`, Ollama/OpenAI/Gemini compat/OpenRouter/vLLM, prompt `v1.4`).
- **Pluggable Inventory Backends (`zerobom.backends`, `plugins/`):**
  - Cloud-agnostic `InventoryBackend` protocol, `zerobom.backends` entry-point registry, hardened CycloneDX (1.4–1.6) & SPDX (2.2–2.3) parser (`InMemoryComponentIndex`), and conformance suite (`assert_backend_conformance`).
  - Built-in enterprise backends: `local_sbom`, `dependency_track`, `oci_sbom` (with in-toto DSSE unwrapping & realm pinning), `k8s_sbom` (Trivy Operator CRDs).
  - Standalone workspace cloud plugins (`zerobom-aws`, `zerobom-gcp`, `zerobom-azure`) covering Security Hub v2, S3 SBOMs, GCP Artifact Analysis, GCS SBOMs, Azure Resource Graph, and Azure Blob SBOMs.
- **CLI, Alerting, Human Triage & CI (`zerobom.cli`, `zerobom.outputs`, `zerobom.triage`, `action.yml`):**
  - Offline `zerobom demo`, pure deterministic `zerobom scan`, `zerobom check`, `zerobom watch`, `zerobom backends`, and `--version`.
  - Rich terminal renderer, JSON report, and SARIF 2.1.0 GitHub Code Scanning exporter.
  - HMAC-SHA256 webhooks, Slack Block Kit alerts, persistent SQLite triage queue (`zerobom triage list|show|approve|reject`), signed Slack callback server & Socket Mode worker (`zerobom triage-worker`), and idempotent `GitHubIssueSyncer`.
  - Reusable composite GitHub Action (`action.yml`) with SQLite state caching, SARIF upload, and script-injection hardening.
- **Benchmarks & Documentation:**
  - Two-tier public benchmark (`benchmarks/run_evals.py`) covering `16` deterministic adversarial offline cases (`100.00%` routing, `0/16` escape) and `46` synthetic pre-CVE + marketing trap dev cases (`97.83%` routing, `100.00%` precision on `gpt-4o-mini` `v1.4`).
  - Zensical + `mkdocstrings-python` documentation site, contributor templates, and OIDC PyPI Trusted Publishing release workflow.
