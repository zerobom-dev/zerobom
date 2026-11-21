# zerobom Project Roadmap

Goal: Build and maintain a reliable, contributor-friendly open-source engine for detecting CVE-less and pre-CVE vulnerabilities in security research blogs against CycloneDX, SPDX, container, Kubernetes, and cloud software inventories using deterministic verification and ecosystem-native version math.

## Phase 1: Core Deterministic Engine & CLI MVP
Objective: Provide a zero-cloud-lock-in local CLI and verification pipeline that runs offline out of the box and isolates LLM extraction behind deterministic checks.

- [x] **1.1 Project Scaffold & Contracts**
  - Initialize `uv` workspace (`src/zerobom/`), `pyproject.toml`, `ruff` (`D` Google docstrings + `S` Bandit security rules), `mypy --strict`, `pytest`.
  - Define strict, immutable Pydantic v2 contracts (`strict=True, extra="forbid", frozen=True`) in `models.py`.
  - Enforce URI scheme allowlists, length ceilings, and C0/C1 control-character rejection at model boundaries.
- [x] **1.2 Deterministic Verification Engine (`verify/`)**
  - `grounding.py`: Two-stage `evidence_quote` verification (exact/normalized article substring match + left/right boundary-aware package/version token confirmation with `re.escape`).
  - `purl.py`: Ecosystem normalization, ASCII coordinate validation, unnamespaced & `generic`-namespace blocklists, canonical PURL builder, and TTL-cached `HttpRegistryChecker` (PyPI/npm/Maven/Go with Solr injection protection and `follow_redirects=False`).
  - `scorer.py`: Two-axis scoring (`source_tier_weight * extraction_specificity`) with `AUTO` (>=0.75), `TRIAGE` (0.50-0.74), and `DROP` (<0.50) routing, hard fail-closed gates, and specificity caps for weak quotes, unbounded zero-days, and registry errors.
  - `osv_compiler.py`: Compile verified claims into OSV 1.6.7-compatible JSON using the explicit non-official local namespace `PRECVE-YYYY-XXXXXXXX` (documenting `Generic` / `CloudLinux` extensions) + `univers` deterministic version evaluation and per-affected evidence quotes.
- [x] **1.3 Cloud-Agnostic Inventory Contract & Local SBOM Backend (`backends/`)**
  - Cloud-agnostic `AssetRef`, `InventoryComponent`, and `PackageQuery` contracts + `InventoryBackend` `Protocol`.
  - `backends/registry.py`: Python plugin discovery via `importlib.metadata.entry_points(group="zerobom.backends")` with `local_sbom` built in.
  - `backends/local_sbom.py` & `sbom_parser.py`: Recursive CycloneDX (1.4-1.6) and SPDX (2.2-2.3) JSON parsing with byte limits, recursion/depth guards, symlink checks, `?distro=` filtering, and `?upstream=` source-package matching.
- [x] **1.4 Hardened Ingestion, State Store & Narrow LLM Extractor (`ingest/`, `extract/`, `sources.yaml`)**
  - `ingest/fetcher.py`: SSRF-hardened `httpx` (`trust_env=False`) + `trafilatura` fetcher blocking non-global IPs across redirects (`<= 3`), streaming byte cap, and `Content-Type` allowlist.
  - `ingest/rss.py` & `ingest/state.py`: Parameterized SQLite state store with `ETag`/`Last-Modified` conditional polling and multi-encoding `expat` DOCTYPE/ENTITY XXE rejection.
  - `ingest/prefilter.py`: Deterministic software/vulnerability pre-filter capturing `known_aliases` before LLM invocation.
  - `extract/`: Swappable `Extractor` protocol, prompt `v1.4` with `<UNTRUSTED_ARTICLE>` fencing and head+tail windowing, bounded responses, `max_tokens`, and OpenAI-compatible `httpx` client.
  - `sources.yaml`: Curated Tier 1 / Tier 2 security blog allowlist validated with `yaml.safe_load` and strict Pydantic models.
- [x] **1.5 Pipeline Orchestrator, CLI, Bundled Demo & Outputs (`pipeline.py`, `cli.py`, `outputs/`, `data/`)**
  - `pipeline.py`: Decoupled end-to-end orchestrator (`ingest -> prefilter -> extract -> verify -> compile_osv -> backend.match -> state`).
  - `cli.py`: `demo`, `scan`, `check`, `watch`, `backends`, `triage`, `triage-worker`, and `--version` with deterministic exit codes.
  - `outputs/`: Rich terminal renderer (with ANSI/OSC-8 & markup sanitization), JSON report, and GitHub Code Scanning SARIF 2.1.0 serializer.
- [x] **1.6 Two-Tier Evaluation Benchmark (`benchmarks/`)**
  - **Offline Deterministic Suite (`16` cases):** CI gate verifying adversarial grounding, blocklist, version math, and routing invariants with zero API keys.
  - **Synthetic Pre-CVE Dev Benchmark (`46` cases):** 36 concise pre-CVE advisory summaries + 10 marketing/prompt-injection traps evaluating prompt `v1.4` and verification gates end to end.

## Phase 2: Pluggable Ecosystem & SecOps Integration
Objective: Provide enterprise SBOM integrations, optional cloud plugins, actionable alerting, and CI automation.

- [x] **2.1 Pluggable Inventory Backends (`zerobom.backends` & `plugins/`)**
  - `assert_backend_conformance` test harness and authoring guide (`docs/PLUGIN_AUTHORING.md`).
  - Built-in enterprise backends: `dependency_track`, `oci_sbom` (with DSSE unwrapping & realm pinning), `k8s_sbom` (Trivy Operator CRDs).
  - Standalone workspace cloud plugins: `zerobom-aws`, `zerobom-gcp`, `zerobom-azure`.
- [x] **2.2 Actionable Alerting & Human-in-the-Loop Triage (`outputs/`, `triage/`)**
  - Stateless signed HMAC-SHA256 webhooks (`WebhookNotifier`) and Slack Block Kit alerts (`SlackNotifier`).
  - Persistent SQLite triage queue + signed HTTP callback / Socket Mode worker (`zerobom triage-worker`) with `X-Slack-Signature` verification and `<3s` acknowledgement.
- [x] **2.3 CI/CD & GitHub Action (`action.yml`)**
  - Reusable composite GitHub Action with SQLite state caching, SARIF upload, and idempotent GitHub Issue sync (`GitHubIssueSyncer`).

## Phase 3: Documentation, Packaging & `v0.1.0` Release
Objective: Finalize accurate OSS documentation, hardened packaging, and release automation before tagging.

- [x] **3.1 Documentation Site & Visuals**
  - `README.md`, offline Rich terminal preview (`docs/assets/demo-preview.svg`), reproducible VHS tape (`docs/assets/demo.tape`), Zensical docs (`zensical.toml`, `docs/`), and `mkdocstrings-python` API reference built with `--strict`.
- [x] **3.2 Community Governance & Contribution Templates**
  - `LICENSE` (`Apache-2.0`), `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `.env.example`, PR template, and GitHub YAML issue forms.
- [ ] **3.3 Release Execution (`v0.1.0` Core First, Cloud Plugins Next)**
  - [x] Hardened core sdist/wheel build config, PyPI OIDC Trusted Publishing workflow (`.github/workflows/release.yml`), and SHA-pinned GitHub Actions.
  - [x] Live re-run & archive of Tier 2 benchmark outputs under `benchmarks/results/`.
  - [ ] Initialize `zerobom-dev/zerobom`, publish core `zerobom` via `v0.1.0` tag, then publish `zerobom-{aws,gcp,azure}` via `plugins-v0.1.0`.

## Planned Post-`v0.1.0` Hardening (`v0.2.0`)
- Pinned-IP `httpcore` socket transport to close DNS-rebinding TOCTOU completely across fetchers and webhooks.
- Held-out real-world full-HTML pre-CVE benchmark corpus (testing `trafilatura` noise and >24 KB documents alongside synthetic dev cases).
- Slack workspace/user allowlists (`allowed_team_ids`/`allowed_user_ids`) and POSIX `0o600` SQLite file permissions.
- Configurable per-host feed crawl delays, `Retry-After` backoff, OpenVEX output, and a read-only GitHub Dependency Graph backend.
