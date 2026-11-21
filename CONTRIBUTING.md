# Contributing to zerobom

Thank you for helping shrink the window between security disclosure and patch verification! Every contribution—whether a new research blog feed, a benchmark case, a backend plugin, or a bug fix—keeps the core deterministic and tightly gated against extraction errors.

## Development Setup

`zerobom` uses **Python 3.11+** and [`uv`](https://docs.astral.sh/uv/):

```bash
uv sync --all-extras
```

Verify the full local test suite before opening a PR:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src/
uv run mypy --strict plugins/zerobom-aws/src plugins/zerobom-gcp/src plugins/zerobom-azure/src
uv run pytest -v
uv run python benchmarks/run_evals.py --mode offline
```

---

## 1-Minute Contribution Recipes

### 1. Add a Security Blog Feed to `sources.yaml`

Add an entry under `feeds:` in [`sources.yaml`](sources.yaml):

```yaml
  - name: "Example Security Research"
    url: "https://research.example.org/feed.xml"
    tier: "tier_1"          # tier_1 (1.0 weight) or tier_2 (0.85 weight)
    kind: "rss"             # rss | sitemap | html_index | auto
    enabled: true
    tags:
      - research
      - open-source
```

Guidelines:
- **`tier_1`:** Original vulnerability research disclosures (e.g., Project Zero, vendor PSIRTs, primary OSS advisories).
- **`tier_2`:** Reputable security engineering aggregators or vendor threat blogs.
- Validate locally before committing:
  ```bash
  uv run python -c "from zerobom.ingest import load_sources_config; load_sources_config('sources.yaml')"
  uv run pytest tests/test_ingest.py -v
  ```

### 2. Add a Pre-CVE Advisory or Marketing Trap to `benchmarks/`

Add a concise, fair-use reproduction fixture matching [`BenchmarkCase`](benchmarks/schema.py) into [`benchmarks/datasets/precve_cases.json`](benchmarks/datasets/precve_cases.json) or [`benchmarks/datasets/marketing_traps.json`](benchmarks/datasets/marketing_traps.json):

```json
{
  "case_id": "precve-pypi-99-example",
  "category": "precve",
  "ecosystem_group": "pypi",
  "article": {
    "url": "https://research.example.org/advisories/example",
    "title": "Pre-CVE: Issue in example-pkg",
    "body": "All versions of example-pkg prior to 1.4.2 are vulnerable; upgrade to 1.4.2.",
    "source_name": "Example Lab",
    "source_tier": "tier_1",
    "published_at": "2026-06-01T12:00:00Z"
  },
  "expected_prefilter_pass": true,
  "expected_routing": "auto",
  "expected_purls": ["pkg:pypi/example-pkg"],
  "version_probes": [
    { "component_purl": "pkg:pypi/example-pkg", "installed_version": "1.4.1", "expected_vulnerable": true },
    { "component_purl": "pkg:pypi/example-pkg", "installed_version": "1.4.2", "expected_vulnerable": false }
  ],
  "notes": "Upper-bounded PyPI regression case."
}
```

Validate offline schema & dataset invariants:

```bash
uv run pytest tests/test_benchmarks.py -v
```

### 3. Author or Submit a `zerobom.backends` Plugin

1. Read the [Plugin Authoring Guide](docs/PLUGIN_AUTHORING.md).
2. Implement `InventoryBackend` and publish an entry point under `[project.entry-points."zerobom.backends"]`.
3. Never evaluate version ranges inside a plugin—return normalized `InventoryComponent` records for `PackageQuery` and let `zerobom.verify.osv_compiler` run `univers` math.
4. Pass `assert_backend_conformance(my_mocked_backend, case)` with 100% mocked SDK/HTTP clients in `pytest`.

---

## Core Engineering & Security Rules

1. **No LLM version math.** Version comparisons remain deterministic in `univers` / `osv_compiler.py`.
2. **No live network or LLM calls in unit tests.** Mock all HTTP, registry, SDK, and LLM clients in `tests/`.
3. **Treat untrusted inputs as hostile.** Never use `eval`, `exec`, `pickle`, `yaml.load` (use `yaml.safe_load`), or `subprocess(..., shell=True)`. Parameterize SQLite queries, disable redirects by default (`follow_redirects=False`), disable implicit proxy env inheritance (`trust_env=False`), and validate package coordinates strictly.
4. **Google-style docstrings & strict typing.** Enforced automatically via `ruff` (`D`, `S`) and `mypy --strict`.
5. **AI-assisted contributions:** `zerobom` itself was developed with AI coding assistance and audited against adversarial inputs. AI-assisted PRs are welcome, provided all invariants, strict type checks, Ruff security/docstring checks, and offline regression tests pass before review.
