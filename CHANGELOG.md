# Changelog

All notable changes to `zerobom` are documented in this file following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-11-25

### Added
- **Extraction Prompt `v1.5` & Article Taxonomy (`zerobom.models`, `zerobom.extract`):**
  - Added `ArticleType` classification (`original_disclosure`, `vendor_advisory`, `malicious_package`, `known_vuln_analysis`, `research_guidance`, `product_announcement`, `benchmark_evaluation`, `offensive_technique`, `non_vulnerability`) and additive `claim_aliases` on `ExtractedPackageClaim`.
  - Removed sample placeholder defaults (`CWE-918`, `CVE-2026-12345`, `2.31.0`) from the `v1.5` prompt JSON schema and added deterministic verbatim boundary checks for `cwe_ids`, `known_aliases`, and `claim_aliases` against article text.
  - Added explicit `exact` (malicious compromise) vs `last_affected` (`through`) vs `fixed` polarity rules and `github` ecosystem extraction guidance.
- **Expanded Verification, PURL & Registry Hardening (`zerobom.verify`):**
  - Enforced grounding of all non-`"0"` claimed version tokens (skipping only implied `.0` branch origins matching the claimed branch prefix/major) plus `::` delimiter normalization in `extract_package_match_candidates`.
  - Added deterministic `check_quote_polarity()` (blocking copyright/banner notices, malicious/compromised packages mislabeled as `fixed`, and inclusive `through`/confirmed bounds paired with `fixed`) and `check_distro_quote_grounding()`.
  - Rejects `fixed="0"` and `last_affected="0"`, detects overlapping multi-branch `introduced="0"` intervals within and across claims (`detect_overlapping_branch_ranges()`), enforces `ArticleType` `DROP`/`TRIAGE` gates, and isolates `AUTO` OSV output strictly to verified bounded `AUTO` claims while recording per-affected `grounding_status`, `registry_status`, and `routing` inside `OsvAffected.database_specific["zerobom"]`.
  - Added `github` PURL normalization + OSV SemVer matching (`GitHubVersionRange`), `_NON_DISTRO_NAMESPACE_BLOCKLIST` (blocking e.g. `pkg:rpm/apache/httpd` while keeping custom Linux distros), expanded `GENERIC_PACKAGE_BLOCKLIST` (`firmware`, `software`, `router`, `model`, `llm`, etc.), and expanded `HttpRegistryChecker` support for `cargo`, `gem`, `nuget`, and `composer`.
- **Ingestion Timestamp & Pre-Filter Improvements (`zerobom.ingest`):**
  - Added `extract_article_metadata_and_text()` with bounded `trafilatura` `metadata.date` fallback and `published_at_inferred` tracking on `FeedEntry` and `RawArticle`.
  - Excluded non-article HTML index routes (`/feed`, `/rss`, `/tag/`, `/category/`, `/author/`, `/page/`) and gated pure product-GA, listicle, and model-benchmark posts lacking concrete flaw/version evidence.
- **Offline Adversarial Benchmarks & Backwards Compatibility:**
  - Expanded `benchmarks/datasets/offline_adversarial.json` from `16` to `23` regression cases (`100.00%` routing & version-probe accuracy, `0.00%` hallucination escape); remains fully additive and compatible with `zerobom-aws`, `zerobom-gcp`, and `zerobom-azure` `0.1.0` plugins.

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
