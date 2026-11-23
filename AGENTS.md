# AGENTS.md — zerobom

## Mission & Architecture Scope
`zerobom` is an open-source CLI and automation engine that hunts **CVE-less / pre-CVE vulnerabilities** published in security blogs against software inventories (CycloneDX, SPDX, OCI, Kubernetes, Dependency-Track, and optional cloud SBOM plugins) before NVD or OSV publishes an entry.

The LLM is strictly a narrow, replaceable ~15% extraction layer returning raw JSON strings. Deterministic verification, canonical package resolution, ecosystem-native version math, and reproducible offline evaluation live in the ~85% deterministic Python core.

Across public web properties, the **Astro live pre-CVE portal** is hosted at `https://zerobom.dev/` in a separate repository (`zerobom-dev/zerobom-portal`, Option A portal-owned 6-hour watch runner), while **Zensical documentation** is hosted at `https://docs.zerobom.dev/` on GitHub Pages from `zerobom-dev/zerobom`.

## Non-Negotiable Engineering Invariants
1. **Never let an LLM compare versions.** The LLM extracts raw version strings only. All version range matching MUST be deterministic using `univers` (paired with `packageurl-python`) across ecosystems (SemVer, PEP 440, Maven, Go, Debian, RPM, Alpine, Cargo, RubyGems, NuGet, Composer).
2. **Verbatim Quote Grounding.** Every extracted package/version claim MUST include an `evidence_quote` verified by exact or normalized substring match with left/right token boundary guards against the raw fetched article text. If grounding fails or tokens are missing/invalid, drop the specificity score immediately.
3. **No Hallucinated Packages.** Resolve fuzzy names (e.g., `"Python requests"`) to canonical ASCII Package URLs (`pkg:pypi/requests`), validate against upstream registries (with TTL caching/mocking in tests, capping upstream `ERROR` responses to `TRIAGE`), and block unnamespaced generic names (`core`, `utils`, `app`, `pkg:generic/*/utils`).
4. **Standard Interchange Formats Only.** Compile verified extractions into OSV 1.6.7-compatible JSON using the explicit non-official local namespace `PRECVE-YYYY-XXXXXXXX` (and explicitly documenting `Generic` / `CloudLinux` as `zerobom` ecosystem extensions outside the strict OSV ecosystem enum). Support **CycloneDX & SPDX JSON** as zero-config defaults; keep remote and public-cloud inventory APIs outside core dependencies via `zerobom.backends` entry points.
5. **Two-Axis Credibility Gate.** Route results deterministically using `composite_score = source_tier_weight * extraction_specificity`:
   - `>= 0.75`: Auto-query SBOM inventory & alert if hits > 0 (`TRIAGE`-only or unbounded claims never compile into `AUTO` advisories).
   - `0.50 - 0.74`: Output/route for human triage approval.
   - `< 0.50`: Log silently / drop.
6. **Zero-Friction First Run.** `zerobom demo` (and `uvx zerobom demo`) MUST work offline with zero API keys using wheel-bundled demo fixtures via `importlib.resources`.

## Tech Stack & Libraries
- **Python 3.11+**, managed with `uv` and `pyproject.toml` (`src/` layout + `plugins/*` workspace).
- **CLI & UI:** `typer` + `rich`.
- **Schemas:** `pydantic` v2 (`strict=True, extra="forbid", frozen=True`).
- **Ingestion:** `httpx` (`trust_env=False` on SSRF-sensitive clients, `DEFAULT_USER_AGENT`), `trafilatura`, `feedparser`, `xml.parsers.expat`, `sqlite3`.
- **LLM Layer (Isolated in `src/zerobom/extract/`):** Pluggable `Extractor` protocol with a lean OpenAI-compatible `httpx` client (`max_tokens`, bounded responses, truncated retries) and optional provider extras.
- **Deterministic Core (`src/zerobom/verify/`):** `packageurl-python`, `univers`.
- **11 Inventory Backends (`zerobom.backends`):** 4 built-in core backends (`local_sbom`, `dependency_track`, `oci_sbom`, `k8s_sbom`) plus 7 optional cloud plugin backends (`aws_security_hub`, `aws_inspector_sbom`, `s3_sbom`, `gcp_artifact_analysis`, `gcs_sbom`, `azure_resource_graph`, `azure_blob_sbom`) under `plugins/` (`zerobom-aws`, `zerobom-gcp`, `zerobom-azure`), strictly outside core dependencies.

## Repository Orientation
- `docs/` & `zensical.toml` — Zensical docs site published at `https://docs.zerobom.dev/` (`docs/ROADMAP.md` excluded from docs site build).
- `sources.yaml` — Curated Tier 1 / Tier 2 security blog RSS/Atom/sitemap/HTML allowlist (synced by `zerobom-portal`).
- `benchmarks/` — Deterministic offline adversarial suite + concise synthetic pre-CVE dev evaluation suite + `run_evals.py`.
- `src/zerobom/models.py` — Canonical Pydantic contracts shared across all modules.
- `src/zerobom/pipeline.py` — Decoupled end-to-end orchestration shared by CLI, demos, and benchmarks.
- `src/zerobom/ingest/` — SSRF-hardened HTTP fetcher, `expat`-guarded RSS/Atom/sitemap/HTML pollers, SQLite state store, deterministic pre-filter (`prefilter.py`, covering vulnerability, enterprise software, and AI/LLM infrastructure signals).
- `src/zerobom/extract/` — Narrow LLM structured extractor + versioned prompts (`v1.4`).
- `src/zerobom/verify/` — `grounding.py`, `purl.py`, `scorer.py`, `osv_compiler.py`.
- `src/zerobom/backends/` — `base.py`, `registry.py`, `conformance.py`, `sbom_parser.py`, `local_sbom.py`, `dependency_track.py`, `oci_sbom.py`, `k8s_sbom.py`.
- `src/zerobom/outputs/` — `terminal.py`, `json_out.py`, `sarif.py`, `webhook.py`, `slack.py`, `github_issue.py`.
- `src/zerobom/triage/` — `store.py`, `actions.py`, `server.py` (human-in-the-loop CLI + Slack callback worker).
- `src/zerobom/data/` — Wheel-bundled demo advisory and sample SBOM fixtures (`importlib.resources`).
- `plugins/` — Companion cloud backend packages (`zerobom-aws`, `zerobom-gcp`, `zerobom-azure`) with strict `sdist` allowlists.
- `scripts/verify_cloud_connectors.py` — Opt-in read-only live cloud sandbox verification script (never run in automated CI).
- `.github/workflows/` — CI, real-wire cloud emulator CI (`cloud-emulators.yml`), Zensical docs (`docs.yml`), demo render (`render-demo.yml`), and PyPI trusted publishing (`release.yml`).

## Coding, Security & Documentation Standards
- **Software Engineering Best Practices:**
  - Prefer pure, small, composable functions and immutable/strict Pydantic models (`strict=True, extra="forbid", frozen=True`).
  - Fail closed on verification boundaries; never rely on `assert` for runtime validation in `src/` (stripped under `python -O`).
  - Keep external I/O behind typed `Protocol` boundaries so core logic stays deterministic and testable offline.
- **Secure, Bug-Resistant & Injection-Proof Coding:**
  - Treat all fetched blog HTML/text, RSS/XML feeds, SBOM/OSV JSON files, package names, version strings, and LLM outputs as **untrusted adversarial input**.
  - **Zero injection surfaces:** Never use `eval`, `exec`, `pickle`, `yaml.load` (use `yaml.safe_load`), or `subprocess(..., shell=True)`. Always use parameterized SQL queries (`?` placeholders) for `sqlite3`. Always escape untrusted literals in regexes (`re.escape`) and validate/encode URL parameters (`urllib.parse.quote`).
  - **SSRF, XXE, DoS, Path Traversal & Terminal Safety:** Enforce explicit URI scheme allowlists, disable implicit proxy env inheritance (`trust_env=False`), guard XML against UTF-8/UTF-16 DOCTYPE/ENTITY declarations via `expat`, catch `RecursionError` alongside `json.JSONDecodeError`, reject/strip C0+C1 ANSI/OSC-8 terminal escape sequences, disable HTTP redirects by default (`follow_redirects=False`), and reject path-traversal segments (`..`, `.`, `\`).
  - **ReDoS & Resource Bounds:** Avoid nested-quantifier backtracking regexes and enforce explicit input/response byte ceilings.
  - **Query-Language Safety:** Validate ASCII package coordinates against strict ecosystem allowlist regexes before building external search/API queries.
- **Cloud Plugin Hardening (`plugins/`):**
  - Use bounded streaming gzip decompression (reject zip bombs), skip archived object tiers cleanly (S3 Glacier / Deep Archive, Azure Archive blobs), refresh OAuth/STS credentials automatically, verify `SBOM_REFERENCE` digests with `hmac.compare_digest`, support sovereign cloud presets where applicable, enforce strict `sdist` include allowlists, and keep all cloud SDKs out of core `zerobom` dependencies.
- **GitHub Actions Hardening (`.github/workflows/` & `action.yml`):**
  - Pin every third-party action to a full 40-character commit SHA.
  - Set top-level `permissions: { contents: read }` and escalate per-job only where needed (`security-events: write`, `issues: write`, `id-token: write`, `pages: write`).
  - Never interpolate `${{ inputs.* }}`, `${{ github.* }}`, or `${{ steps.* }}` directly inside `run:` shell commands; pass untrusted/dynamic values strictly through `env:`.
- **OSS-Ready Docstrings & Comments:**
  - Write **Google-style docstrings** on every public module, class, method, and function in `src/` and `plugins/*/src/`, and comment non-obvious invariants.
  - Enforce via Ruff (`D` Google convention + `S` bandit checks) and `mypy --strict`.

## Commands & Verification Gates
- Install dev env: `uv sync --all-extras`
- Run full test suite (`14` modules; `test_cloud_emulators.py` uses `@pytest.mark.emulator`): `uv run pytest`
- Lint & format: `uv run ruff check . && uv run ruff format --check .`
- Type check all packages: `uv run mypy src/ && uv run mypy --strict benchmarks/ && uv run mypy --strict plugins/zerobom-aws/src plugins/zerobom-gcp/src plugins/zerobom-azure/src scripts/`
- Run offline benchmark gate: `uv run python benchmarks/run_evals.py --mode offline`
- Build strict docs site: `uv run zensical build --clean --strict`
- Run packaging & workflow guardrails: `uv run pytest tests/test_release_and_docs.py`
- Verify cloud connectors manually (read-only sandbox): `uv run python scripts/verify_cloud_connectors.py`
- Run offline demo: `uv run zerobom demo`

## Agent Rules & Context Hygiene
- **Do NOT read large raw SBOM JSON or HTML files directly into context.** Inspect fixture structure via targeted scripts; keep test SBOM fixtures minimal (< 100 lines).
- **No live network or LLM calls in unit tests.** Mock HTTP, registries, cloud SDKs, and LLM responses; keep live evals strictly inside `benchmarks/run_evals.py` and sandbox checks inside `scripts/verify_cloud_connectors.py`.
- **Keep diffs scoped.** Implement one module/feature at a time and run `uv run pytest && uv run ruff check .` before finishing any task.
- **No secrets in repo.** Never commit `.env`, API keys, account IDs, or internal SBOMs.
